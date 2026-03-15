"""
Tool-augmented filter agent: uses LLM with ripgrep, shell, and Foundry to classify
Slither findings as true positives (exploitable) or false positives.
"""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import litellm

from agent.agent_tools import FILTER_AGENT_TOOLS, AgentToolExecutor
from agent.llm.base import FilterResult
from tools.foundry.foundry_runner import FoundryRunner

logger = logging.getLogger(__name__)

SUBMIT_PREFIX = "__SUBMIT_TRUE_POSITIVES__"
MAX_TURN_COUNT = 40

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
})


def _prefilter_findings(findings: list[dict]) -> list[dict]:
    """Return findings that are worth sending to the agent (exclude obvious non-exploitable)."""
    return [f for f in findings if (f.get("check_type") or "").strip() not in SKIP_CHECK_TYPES]


def _finding_summary(finding: dict) -> dict:
    """One-line summary for the prompt."""
    desc = (finding.get("description") or "")[:200]
    return {
        "id": finding.get("id"),
        "check_type": finding.get("check_type"),
        "contract": finding.get("contract"),
        "function": finding.get("function"),
        "description": desc,
    }


def run_agent_loop(
    system: str,
    user_content: str,
    tools: list[dict],
    executor: AgentToolExecutor,
    model_id: str,
    max_turns: int = MAX_TURN_COUNT,
    submit_prefix: str = SUBMIT_PREFIX,
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
            if name == "shell" and args.get("command"):
                logger.info("    Agent tool: %s  command: %s", name, args["command"])
            else:
                logger.info("    Agent tool: %s  args: %s", name, args)
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
) -> list[FilterResult]:
    """
    Run the filter agent: LLM uses ripgrep, shell, Foundry, and get_finding_detail to decide
    which findings are true positives (exploitable). Returns one FilterResult per finding.
    """
    if api_key:
        litellm.anthropic_key = api_key
    model_id = f"anthropic/{model}" if not model.startswith("anthropic/") else model

    candidates = _prefilter_findings(findings)
    skipped = len(findings) - len(candidates)
    if skipped:
        logger.info("  Pre-filtered %d obviously non-exploitable finding(s); %d candidate(s) sent to agent.", skipped, len(candidates))
    if not candidates:
        logger.info("  No candidates after pre-filter; skipping agent.")
        return _results_for_findings(findings, [])

    findings_by_id = {f["id"]: f for f in findings}

    executor = AgentToolExecutor(
        repo_path=repo_path,
        foundry_runner=foundry_runner,
        findings_by_id=findings_by_id,
    )
    executor.warm_foundry_build_cache()

    summary_list = [_finding_summary(f) for f in candidates]
    system = """You are a Solidity security auditor. You have been given a SUMMARY of static analysis findings from Slither.

Your goal: determine which findings are TRUE POSITIVES (real, exploitable bugs), verify each one, then submit with exploit scenarios.

Tools:
- get_finding_detail(finding_id): get the full JSON for one finding (location, description, etc.).
- ripgrep: search the repo for patterns. Use to find code and usages.
- shell: run commands in the repo root (e.g. cat, ls, rm). Use 'rm <path>' to delete the exploit test file after verification.
- read_file(path): read a file (path relative to repo root). Use to read source before writing a fix.
- write_file(path, content): write content to a file. Use to create the exploit test, apply the fix, and revert the fix.
- foundry_build: cached result of forge build.
- foundry_test(match_path, match_contract): run forge test, optionally filtered.
- submit_true_positives: call ONLY when done. Pass finding_ids and exploit_scenarios (map of finding_id -> short description of the exploit).

VERIFICATION WORKFLOW (you MUST do this for every finding you mark as true positive):
1. Write the exploit test: use write_file to create a Foundry test file (e.g. test/Exploit_<name>.t.sol) that demonstrates the bug.
2. Run the test: call foundry_test with match_path so the new test runs. The test MUST pass (exploit succeeds).
3. Apply the fix: read the vulnerable source with read_file, produce the fixed Solidity code, write it with write_file to the same path.
4. Run the test again: call foundry_test. The test MUST fail (fix blocks the exploit).
5. Revert the fix: write_file the original source content back so the repo is unchanged.
6. Delete the test file: use shell with 'rm test/Exploit_<name>.t.sol' (or the path you used).
7. Only then include that finding in submit_true_positives with its exploit_scenario (1-3 sentences describing how the exploit works).

Rules:
1. Use get_finding_detail, ripgrep, read_file, and shell to understand the codebase and each finding.
2. Only mark a finding as true positive if you completed the full workflow (write test, pass, fix, fail, revert, delete) for it.
3. Call submit_true_positives only once, at the end, with finding_ids and exploit_scenarios for every verified finding. Do not call any other tools after that.
4. If you cannot verify a finding (e.g. test does not pass or fix does not make it fail), do not include it in submit_true_positives."""

    user_content = f"""Repository path: {repo_path}

Slither findings summary (use get_finding_detail(finding_id) to get full JSON for any finding):

{json.dumps(summary_list, indent=2)}

For each finding you believe is a true positive: use the tools to verify it with the full workflow (write exploit test, run pass, apply fix, run fail, revert fix, delete test file). Then call submit_true_positives once with all verified finding IDs and their exploit_scenarios."""

    payload, _ = run_agent_loop(
        system=system,
        user_content=user_content,
        tools=FILTER_AGENT_TOOLS,
        executor=executor,
        model_id=model_id,
    )

    if payload is not None:
        ids = payload.get("finding_ids", [])
        reasons = payload.get("reasons") or {}
        exploit_scenarios = payload.get("exploit_scenarios") or {}
        return _results_for_findings(findings, ids, reasons, exploit_scenarios)

    logger.warning("Filter agent hit max turns or no tool call; treating as no true positives.")
    return _results_for_findings(findings, [], None, {})


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
