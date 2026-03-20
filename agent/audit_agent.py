"""
Orchestrates the Solidity audit: Slither → tool-augmented LLM (filter + verify) → report.

Enhanced with intelligent context management:
- Semantic graph for dependency analysis
- Call graph for cross-contract tracing
- Git context for regression detection
- Token-optimized context assembly
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from tools.execution.base import ExecutionEnvironment
from tools.slither.slither_runner import SlitherRunner
from tools.foundry.foundry_runner import FoundryRunner
from agent.llm.base import LLMClient, FilterResult, ExploitTestResult, BugReportEntry
from agent.report import report_to_markdown
from agent.filter_agent import run_filter_agent
from context.context_manager import ContextManager, ContextConfig

if TYPE_CHECKING:
    from agent.cli_output import CliOutput


@dataclass
class AuditConfig:
    """Configuration for a single audit run."""

    repo_path: Path
    target_file: Path | None = None
    slither_output_path: str = "slither_findings.json"
    report_output_path: str = "audit_report.md"
    execution_env: ExecutionEnvironment | None = None
    llm_client: LLMClient | None = None
    llm_model: str = "claude-sonnet-4-20250514"
    llm_api_key: str | None = None
    filter_model: str | None = None
    context_config: ContextConfig | None = None


@dataclass
class AuditResult:
    """Result of an audit run."""

    findings_raw: list[dict] = field(default_factory=list)
    filter_results: list[FilterResult] = field(default_factory=list)
    true_positive_findings: list[dict] = field(default_factory=list)
    exploit_tests: list[tuple[dict, ExploitTestResult]] = field(default_factory=list)
    report_entries: list[BugReportEntry] = field(default_factory=list)
    report_markdown_path: Path | None = None
    errors: list[str] = field(default_factory=list)


class AuditAgent:
    def __init__(self, config: AuditConfig, cli: "CliOutput | None" = None):
        from tools.execution.local import LocalExecutionEnvironment
        from agent.llm.llm_client import AnthropicLiteLLMClient

        self.config = config
        self.executor = config.execution_env or LocalExecutionEnvironment()
        self.llm = config.llm_client or AnthropicLiteLLMClient()
        self.slither_runner = SlitherRunner(executor=self.executor)
        self.foundry_runner = FoundryRunner(executor=self.executor)
        self.repo_path = Path(config.repo_path).resolve()
        self.report_entries: list[BugReportEntry] = []
        self.cli = cli

        context_config = config.context_config or ContextConfig()
        self.context_manager = ContextManager(self.repo_path, context_config)

    def run(self) -> AuditResult:
        result = AuditResult()
        cwd = self.repo_path
        cli = self.cli

        # ── Stage 1: Index Repository ──────────────────────────────
        if cli:
            cli.stage(1, 4, "Indexing Repository")

        try:
            # Show what we're scanning
            sol_files = list(cwd.rglob("*.sol"))
            skip_dirs = {"node_modules", ".git", "lib", "cache", "out", "artifacts"}
            sol_files = [
                f for f in sol_files
                if not any(skip in f.parts for skip in skip_dirs)
            ]
            if cli:
                cli.info(f"Scanning {len(sol_files)} Solidity files")

            with cli.spinner("Building semantic graph...") if cli else nullcontext():
                self.context_manager.index()

            stats = self.context_manager.get_stats()
            sg = stats["semantic_graph"]
            cg = stats.get("call_graph") or {}
            git = stats.get("git") or {}

            if cli:
                cli.success(f"Indexed {sg['contracts']} contracts from {sg['files_indexed']} files")
                with cli.indent():
                    cli.info(f"{sg['functions']} functions, {sg['edges']} dependency edges")
                    if cg:
                        cli.info(f"Call graph: {cg['total_edges']} calls ({cg['external_calls']} external)")
                    if git.get("available"):
                        cli.info(f"Git: {git.get('total_commits', '?')} commits, {git.get('contributors', '?')} contributors")

                # List contracts found
                if self.context_manager.semantic_graph.contracts:
                    cli.info("Contracts found:")
                    with cli.indent():
                        for name, contract in sorted(self.context_manager.semantic_graph.contracts.items()):
                            func_count = len(contract.functions)
                            cli.info(f"{name} ({contract.contract_type}) — {func_count} functions")

        except Exception as e:
            if cli:
                cli.warning(f"Context indexing failed: {e}")

        # ── Stage 2: Run Slither ───────────────────────────────────
        print()
        if cli:
            cli.stage(2, 4, "Running Slither Static Analysis")

        try:
            if self.config.target_file:
                target = Path(self.config.target_file).resolve()
                if cli:
                    cli.info(f"Target: {target.name}")
                findings = self.slither_runner.run_slither_file(
                    target,
                    output_path=str(cwd / self.config.slither_output_path),
                    cwd=cwd,
                )
            else:
                with cli.spinner("Running Slither analysis...") if cli else nullcontext():
                    findings = self.slither_runner.run_slither_repo(
                        cwd,
                        output_path=str(cwd / self.config.slither_output_path),
                        cwd=cwd,
                    )
        except Exception as e:
            result.errors.append(f"Slither failed: {e}")
            if cli:
                cli.error(f"Slither failed: {e}")
            return result

        result.findings_raw = findings
        if cli:
            cli.success(f"Found {len(findings)} issues")
            # Show breakdown by severity
            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "unknown").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            with cli.indent():
                for sev in ["critical", "high", "medium", "low", "informational", "optimization"]:
                    if sev in severity_counts:
                        color = cli._severity_color(sev)
                        cli.info(f"{color}{sev.upper()}\033[0m: {severity_counts[sev]}")

        if not findings:
            if cli:
                cli.info("No findings to analyze")
            return result

        # ── Stage 3: Build Context ─────────────────────────────────
        print()
        if cli:
            cli.stage(3, 4, "Building Context")

        finding_contexts = {}
        try:
            with cli.spinner("Analyzing dependencies and call paths...") if cli else nullcontext():
                finding_contexts = self.context_manager.build_context_for_findings(findings)
            if cli:
                cli.success(f"Built context for {len(finding_contexts)} findings")
        except Exception as e:
            if cli:
                cli.warning(f"Context building failed: {e}")

        # ── Stage 4: LLM Verification ──────────────────────────────
        print()
        if cli:
            cli.stage(4, 4, "LLM Verification")

        try:
            filter_model = (
                getattr(self.config, "filter_model", None)
                or getattr(self.config, "llm_model", "claude-sonnet-4-20250514")
            )
            if cli:
                cli.info(f"Using model: {filter_model}")

            filter_results = run_filter_agent(
                findings=findings,
                repo_path=cwd,
                foundry_runner=self.foundry_runner,
                model=filter_model,
                api_key=getattr(self.config, "llm_api_key", None),
                finding_contexts=finding_contexts,
                context_manager=self.context_manager,
                cli=cli,
            )
        except Exception as e:
            result.errors.append(f"Filter agent failed: {e}")
            if cli:
                cli.error(f"Filter agent failed: {e}")
            return result

        result.filter_results = filter_results
        finding_by_id = {f["id"]: f for f in findings}
        true_ids = [r.finding_id for r in filter_results if r.is_true_positive]
        result.true_positive_findings = [
            finding_by_id[i] for i in true_ids if i in finding_by_id
        ]

        tp_count = len(result.true_positive_findings)
        fp_count = len(findings) - tp_count
        if cli:
            cli.success(f"Verified {tp_count} true positives, {fp_count} false positives")

        # Build report entries
        if cli and result.true_positive_findings:
            cli.info("Confirmed vulnerabilities:")
            with cli.indent():
                for finding in result.true_positive_findings:
                    try:
                        entry = self.llm.generate_report_entry(
                            finding, 
                            next(
                                (r.exploit_scenario for r in filter_results 
                                 if r.finding_id == finding["id"]),
                                "Exploit verified by agent."
                            )
                        )
                        result.report_entries.append(entry)
                        cli.finding(
                            0,
                            finding.get("check_type", ""),
                            finding.get("severity", ""),
                            finding.get("contract", ""),
                            finding.get("function", ""),
                        )
                    except Exception as e:
                        result.errors.append(f"Report entry for {finding.get('id')}: {e}")

        # Write report
        if result.report_entries:
            report_path = cwd / self.config.report_output_path
            report_to_markdown(result.report_entries, report_path)
            result.report_markdown_path = report_path

        return result

    @staticmethod
    def _reset():
        return "\033[0m"


class nullcontext:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
