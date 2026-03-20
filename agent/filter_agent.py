"""
Tool-augmented filter agent: uses LLM with ripgrep, shell, and Foundry to classify
Slither findings as true positives (exploitable) or false positives.

Enhanced with intelligent context from semantic graph, call graph, and git history.
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING

import litellm

# Configure litellm for better rate limit handling
litellm.num_retries = 5
litellm.retry_after = 10  # Base retry delay in seconds
litellm.request_timeout = 120  # Timeout per request

from agent.agent_tools import FILTER_AGENT_TOOLS, AgentToolExecutor
from agent.llm.base import FilterResult
from tools.foundry.foundry_runner import FoundryRunner

if TYPE_CHECKING:
    from context.context_manager import ContextManager
    from agent.cli_output import CliOutput

logger = logging.getLogger(__name__)

SUBMIT_PREFIX = "__SUBMIT_TRUE_POSITIVES__"
MAX_TURN_COUNT = 40
RATE_LIMIT_DELAY = 0.5  # Seconds between LLM calls to avoid rate limiting

# Pre-filter: skip these check types (not exploitable in practice).
SKIP_CHECK_TYPES = frozenset({
    "solc-version",
    "naming-convention",
    "similar-names",
    "pragma",
    "external-function",
    "low-level-calls",
    "code-complexity",
    "function-state-mutability",
    "cache-array-length",
    "immutable-states",
})

# Check types that are always true positives (no exploit test needed)
AUTO_TRUE_POSITIVE_TYPES = frozenset({
    "weak-prng",
    "incorrect-equality",
    "locked-ether",
    "reentrancy-unlimited-gas",
    "reentrancy-eth",
    "arbitrary-send-eth",
    "timestamp",
    "tx-origin",
    "controlled-delegatecall",
    "suicidal",
    "uninitialized-state",
    "uninitialized-storage",
    "arbitrary-send-eth",
})

# Severity overrides for Slither findings (fix severity inflation)
SEVERITY_OVERRIDES = {
    "reentrancy-unlimited-gas": "medium",  # Slither often marks this informational but it can be real
    "calls-loop": "medium",  # DoS via unbounded loop
    "locked-ether": "medium",  # Funds permanently stuck
    "timestamp": "low",
    "missing-zero-check": "low",
}


def _prefilter_findings(findings: list[dict]) -> list[dict]:
    """Return findings that are worth sending to the agent (exclude obvious non-exploitable)."""
    return [f for f in findings if (f.get("check_type") or "").strip() not in SKIP_CHECK_TYPES]


def _apply_severity_overrides(finding: dict) -> dict:
    """Apply severity overrides to fix Slither's severity inflation."""
    check_type = (finding.get("check_type") or "").strip()
    if check_type in SEVERITY_OVERRIDES:
        finding = dict(finding)  # Don't mutate original
        finding["severity"] = SEVERITY_OVERRIDES[check_type]
    return finding


def _finding_summary(finding: dict) -> dict:
    """One-line summary for the prompt, with severity overrides applied."""
    finding = _apply_severity_overrides(finding)
    desc = (finding.get("description") or "")[:200]
    return {
        "id": finding.get("id"),
        "check_type": finding.get("check_type"),
        "contract": finding.get("contract"),
        "function": finding.get("function"),
        "severity": finding.get("severity", "unknown"),
        "description": desc,
        "is_auto_true_positive": (finding.get("check_type") or "").strip() in AUTO_TRUE_POSITIVE_TYPES,
    }


def run_agent_loop(
    system: str,
    user_content: str,
    tools: list[dict],
    executor: AgentToolExecutor,
    model_id: str,
    max_turns: int = MAX_TURN_COUNT,
    submit_prefix: str = SUBMIT_PREFIX,
    cli: "CliOutput | None" = None,
):
    """
    Generic agent loop: messages + tools, execute tool calls (in parallel), repeat until
    a tool returns a result starting with submit_prefix, then parse and return the payload.
    Returns (payload_dict, None) on submit, or (None, final_messages) on max turns / no tool calls.
    """
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]

    def _tc_id(tc):
        return tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)

    def _tc_fn(tc):
        return tc.get("function", {}) if isinstance(tc, dict) else getattr(tc, "function", None)

    def _tc_name(tc):
        fn = _tc_fn(tc)
        return fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")

    def _tc_args(tc):
        fn = _tc_fn(tc)
        a = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", None)
        return a or ""

    for _ in range(max_turns):
        # Small delay to avoid rate limiting
        if RATE_LIMIT_DELAY > 0:
            time.sleep(RATE_LIMIT_DELAY)
        
        response = litellm.completion(
            model=model_id,
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        choice = response.choices[0]
        msg = choice.message
        tool_calls = getattr(msg, "tool_calls", None) or []
        content = getattr(msg, "content", None) or ""
        if content and isinstance(content, str) and content.strip():
            logger.info("Model: %s", content.strip())

        if not tool_calls:
            if content and isinstance(content, str) and content.strip():
                logger.warning("Agent returned text without tool call: %s", content[:300])
            return None, messages

        messages.append({
            "role": "assistant",
            "content": getattr(msg, "content", None) or None,
            "tool_calls": [
                {"id": _tc_id(tc), "type": "function", "function": {"name": _tc_name(tc), "arguments": _tc_args(tc)}}
                for tc in tool_calls
            ],
        })

        # Execute all tool calls in parallel
        def run_one(tc):
            name = _tc_name(tc)
            try:
                args = json.loads(_tc_args(tc)) if _tc_args(tc) else {}
            except json.JSONDecodeError:
                args = {}
            
            # Show tool call
            if cli:
                summary = ""
                if name == "shell" and args.get("command"):
                    summary = args["command"][:60]
                elif name == "write_file" and args.get("path"):
                    summary = args["path"]
                elif name == "read_file" and args.get("path"):
                    summary = args["path"]
                elif name == "foundry_test" and args.get("match_path"):
                    summary = args["match_path"]
                elif name == "get_finding_detail" and args.get("finding_id"):
                    summary = args["finding_id"][:8] + "..."
                elif name == "get_contract_info" and args.get("contract_name"):
                    summary = args["contract_name"]
                elif name == "get_call_chain" and args.get("contract_name"):
                    summary = f"{args['contract_name']}.{args.get('function_name', '?')}"
                elif args:
                    summary = str(args)[:60]
                cli.tool_call(name, summary)
            
            result = executor.run(name, args)
            return _tc_id(tc), name, result

        results_by_id = {}
        with ThreadPoolExecutor(max_workers=min(8, len(tool_calls))) as pool:
            futures = [pool.submit(run_one, tc) for tc in tool_calls]
            for fut in as_completed(futures):
                tc_id, name, result = fut.result()
                results_by_id[tc_id] = (name, result)

        # Append tool results in the same order as tool_calls; check for submit
        for tc in tool_calls:
            tc_id = _tc_id(tc)
            name, result = results_by_id.get(tc_id, ("", ""))
            if name == "submit_true_positives" and result.startswith(submit_prefix):
                payload_str = result[len(submit_prefix) :].strip()
                try:
                    payload = json.loads(payload_str)
                    return payload, None
                except json.JSONDecodeError:
                    logger.warning("Could not parse submit payload.")
                    return {"finding_ids": [], "reasons": {}}, None
            messages.append({"role": "tool", "tool_call_id": tc_id, "name": name, "content": result})

    return None, messages


def run_filter_agent(
    findings: list[dict],
    repo_path: Path,
    foundry_runner: FoundryRunner,
    model: str = "claude-sonnet-4-20250514",
    api_key: str | None = None,
    finding_contexts: dict[str, str] | None = None,
    context_manager: "ContextManager | None" = None,
    batch_size: int = 10,
    cli: "CliOutput | None" = None,
) -> list[FilterResult]:
    """
    Run the filter agent: LLM uses ripgrep, shell, Foundry, and get_finding_detail to decide
    which findings are true positives (exploitable). Returns one FilterResult per finding.
    
    Args:
        findings: List of Slither findings
        repo_path: Path to the repository
        foundry_runner: Foundry runner instance
        model: LLM model to use
        api_key: API key for the LLM
        finding_contexts: Pre-built context for each finding (from ContextManager)
        context_manager: ContextManager instance for dynamic context queries
        batch_size: Number of findings to process per batch (avoids rate limiting)
    """
    if api_key:
        # Set key based on provider
        if model.startswith("gpt-") or model.startswith("o1") or model.startswith("o3") or model.startswith("openai/"):
            litellm.openai_key = api_key
        else:
            litellm.anthropic_key = api_key
    
    # Normalize model ID
    if "/" in model:
        model_id = model
    elif model.startswith("gpt-") or model.startswith("o1") or model.startswith("o3"):
        model_id = f"openai/{model}"
    else:
        model_id = f"anthropic/{model}"

    candidates = _prefilter_findings(findings)
    skipped = len(findings) - len(candidates)
    if skipped:
        if cli:
            cli.info(f"Pre-filtered {skipped} non-exploitable findings, {len(candidates)} candidates")
    if not candidates:
        if cli:
            cli.info("No candidates after pre-filter")
        return _results_for_findings(findings, [])

    findings_by_id = {f["id"]: f for f in findings}

    executor = AgentToolExecutor(
        repo_path=repo_path,
        foundry_runner=foundry_runner,
        findings_by_id=findings_by_id,
        context_manager=context_manager,
    )
    
    if cli:
        with cli.spinner("Compiling contracts..."):
            executor.warm_foundry_build_cache()
    else:
        executor.warm_foundry_build_cache()

    # Process findings in batches to avoid rate limiting
    all_true_positive_ids = []
    all_reasons = {}
    all_exploit_scenarios = {}
    
    total_batches = (len(candidates) + batch_size - 1) // batch_size
    
    for batch_num, batch_start in enumerate(range(0, len(candidates), batch_size), 1):
        batch_end = min(batch_start + batch_size, len(candidates))
        batch = candidates[batch_start:batch_end]
        
        if cli:
            print()
            # Show findings in this batch
            cli.info(f"Batch {batch_num}/{total_batches} — Analyzing {len(batch)} findings:")
            with cli.indent():
                for f in batch:
                    sev = f.get("severity", "unknown")
                    cli.finding(
                        0,
                        f.get("check_type", ""),
                        sev,
                        f.get("contract", ""),
                        f.get("function", ""),
                    )
            print()
        
        batch_result = _run_filter_batch(
            batch=batch,
            repo_path=repo_path,
            executor=executor,
            model_id=model_id,
            finding_contexts=finding_contexts,
            context_manager=context_manager,
            cli=cli,
        )
        
        if batch_result:
            batch_tp = batch_result.get("finding_ids", [])
            all_true_positive_ids.extend(batch_tp)
            all_reasons.update(batch_result.get("reasons", {}))
            all_exploit_scenarios.update(batch_result.get("exploit_scenarios", {}))
            
            if cli and batch_tp:
                cli.success(f"Batch {batch_num}: {len(batch_tp)} confirmed")
        
        # Delay between batches
        if batch_end < len(candidates):
            if cli:
                cli.info("Waiting before next batch...")
            time.sleep(2)

    return _results_for_findings(findings, all_true_positive_ids, all_reasons, all_exploit_scenarios)


def _run_filter_batch(
    batch: list[dict],
    repo_path: Path,
    executor: AgentToolExecutor,
    model_id: str,
    finding_contexts: dict[str, str] | None = None,
    context_manager: "ContextManager | None" = None,
    cli: "CliOutput | None" = None,
) -> dict | None:
    """Run the filter agent on a batch of findings."""
    summary_list = [_finding_summary(f) for f in batch]

    # Build context section for the system prompt
    context_section = ""
    if context_manager:
        try:
            project_context = context_manager.get_context_for_agent(batch)
            context_section = f"""
PROJECT CONTEXT (from semantic analysis):
{project_context}

"""
        except Exception as e:
            logger.warning("Failed to build project context: %s", e)

    system = f"""You are a Solidity security auditor. You have been given a SUMMARY of static analysis findings from Slither.
{context_section}
Your goal: determine which findings are TRUE POSITIVES (real, exploitable bugs), verify each one, then submit with exploit scenarios.

CRITICAL RULES:
- Findings marked "is_auto_true_positive": true are ALMOST ALWAYS real vulnerabilities. Do NOT dismiss them without thorough analysis.
- For weak-prng, incorrect-equality, timestamp findings: These are real vulnerabilities even if exploit tests are hard to write. Mark them as true positives with an explanation of the attack vector.
- For locked-ether: Any contract with a payable receive/fallback but no withdraw function permanently locks funds. Always a true positive.
- For reentrancy-eth, reentrancy-unlimited-gas: Check if state is updated AFTER external calls. If so, it's a true positive.
- For arbitrary-send-eth: If ETH can be sent to an attacker-controlled address, it's a true positive.

Tools:
- get_finding_detail(finding_id): get the full JSON for one finding (location, description, etc.).
- ripgrep: search the repo for patterns. Use to find code and usages.
- shell: run commands in the repo root (e.g. cat, ls, rm). Use 'rm <path>' to delete the exploit test file after verification.
- read_file(path): read a file (path relative to repo root). Use to read source before writing a fix.
- write_file(path, content): write content to a file. Use to create the exploit test, apply the fix, and revert the fix.
- foundry_build: cached result of forge build.
- foundry_test(match_path, match_contract): run forge test, optionally filtered.
- get_contract_info(contract_name): get detailed info about a contract (functions, state vars, dependencies).
- get_call_chain(contract_name, function_name): trace call chains to understand execution flow.
- get_data_flow(contract_name, function_name, variable): trace data flow for a variable.
- submit_true_positives: call ONLY when done. Pass finding_ids and exploit_scenarios (map of finding_id -> short description of the exploit).

VERIFICATION WORKFLOW - Use ONE of these approaches:

APPROACH A (for findings where exploit tests are feasible):
1. Write the exploit test: use write_file to create a Foundry test file (e.g. test/Exploit_<name>.t.sol) that demonstrates the bug.
2. Run the test: call foundry_test with match_path so the new test runs. The test MUST pass (exploit succeeds).
3. Apply the fix: read the vulnerable source with read_file, produce the fixed Solidity code, write it with write_file to the same path.
4. Run the test again: call foundry_test. The test MUST fail (fix blocks the exploit).
5. Revert the fix: write_file the original source content back so the repo is unchanged.
6. Delete the test file: use shell with 'rm test/Exploit_<name>.t.sol' (or the path you used).

APPROACH B (for findings where exploit tests are NOT feasible - weak-prng, locked-ether, timestamp, missing-zero-check):
1. Read the vulnerable code with read_file to understand the issue.
2. Verify the vulnerability exists by reading the source code.
3. Document the attack vector in the exploit_scenario (how an attacker would exploit this in production).
4. Include in submit_true_positives.

APPROACH C (for reentrancy findings):
1. Trace the call chain to understand the reentrancy path.
2. Verify state is updated AFTER the external call (checks-effects-interactions violation).
3. Write an exploit test showing the reentrancy.
4. If exploit test is feasible, use Approach A. Otherwise, use Approach B.

IMPORTANT: You MUST include ALL findings that are real vulnerabilities in submit_true_positives. Do not skip findings just because they are hard to test.

Rules:
1. Use get_finding_detail, ripgrep, read_file, shell, get_contract_info, get_call_chain, and get_data_flow to understand the codebase and each finding.
2. Mark findings as true positive if the vulnerability EXISTS in the code, even if exploit tests are hard to write.
3. Call submit_true_positives only once, at the end, with finding_ids and exploit_scenarios for every verified finding. Do not call any other tools after that.
4. Pay attention to cross-contract calls, storage access patterns, and data flow when analyzing findings.
5. NEVER change the severity of a finding - use the severity from the finding summary."""

    # Build user content with finding summaries and contexts
    user_content_parts = [f"Repository path: {repo_path}\n"]
    user_content_parts.append("Slither findings summary (use get_finding_detail(finding_id) to get full JSON for any finding):\n")

    for summary in summary_list:
        finding_id = summary["id"]
        user_content_parts.append(json.dumps(summary, indent=2))
        
        # Add pre-built context if available
        if finding_contexts and finding_id in finding_contexts:
            context = finding_contexts[finding_id]
            # Truncate context to avoid token overflow
            if len(context) > 5000:
                context = context[:5000] + "\n... (context truncated, use get_finding_detail for full info)"
            user_content_parts.append(f"\nContext for {finding_id}:\n{context}\n")

    user_content_parts.append("\nFor each finding you believe is a true positive: use the tools to verify it with the full workflow (write exploit test, run pass, apply fix, run fail, revert fix, delete test file). Then call submit_true_positives once with all verified finding IDs and their exploit_scenarios.")

    user_content = "\n".join(user_content_parts)

    if cli:
        cli.info("Sending to LLM for analysis...")

    payload, _ = run_agent_loop(
        system=system,
        user_content=user_content,
        tools=FILTER_AGENT_TOOLS,
        executor=executor,
        model_id=model_id,
        cli=cli,
    )

    if payload is not None:
        return payload

    logger.warning("Filter agent hit max turns or no tool call; treating as no true positives.")
    return {"finding_ids": [], "reasons": {}, "exploit_scenarios": {}}


def _results_for_findings(
    findings: list[dict],
    true_positive_ids: list[str],
    reasons: dict | None = None,
    exploit_scenarios: dict | None = None,
) -> list[FilterResult]:
    reasons = reasons or {}
    exploit_scenarios = exploit_scenarios or {}
    id_set = set(true_positive_ids)
    return [
        FilterResult(
            finding_id=f["id"],
            is_true_positive=f["id"] in id_set,
            reason=reasons.get(f["id"], ""),
            exploit_scenario=exploit_scenarios.get(f["id"], ""),
        )
        for f in findings
    ]
