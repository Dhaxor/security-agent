"""
Orchestrates the Solidity audit: Slither → tool-augmented LLM (filter + verify: write test, pass, fix, fail, revert, delete) → report.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

from tools.execution.base import ExecutionEnvironment
from tools.slither.slither_runner import SlitherRunner
from tools.foundry.foundry_runner import FoundryRunner
from agent.llm.base import LLMClient, FilterResult, ExploitTestResult, BugReportEntry
from agent.report import report_to_markdown
from agent.filter_agent import run_filter_agent


@dataclass
class AuditConfig:
    """Configuration for a single audit run."""

    repo_path: Path
    """Foundry project root (directory containing foundry.toml or src/)."""
    target_file: Path | None = None
    """If set, run Slither only on this file; otherwise run on the whole repo."""
    slither_output_path: str = "slither_findings.json"
    report_output_path: str = "audit_report.md"
    execution_env: ExecutionEnvironment | None = None
    llm_client: LLMClient | None = None
    llm_model: str = "claude-sonnet-4-20250514"
    llm_api_key: str | None = None
    filter_model: str | None = None  # If set, use this (e.g. cheaper) model for the filter agent only.


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
    def __init__(self, config: AuditConfig):
        from tools.execution.local import LocalExecutionEnvironment
        from agent.llm.anthropic_litellm import AnthropicLiteLLMClient

        self.config = config
        self.executor = config.execution_env or LocalExecutionEnvironment()
        self.llm = config.llm_client or AnthropicLiteLLMClient()
        self.slither_runner = SlitherRunner(executor=self.executor)
        self.foundry_runner = FoundryRunner(executor=self.executor)
        self.repo_path = Path(config.repo_path).resolve()
        self.report_entries: list[BugReportEntry] = []

    def _gather_repo_context(self, max_chars_per_file: int = 15000) -> str:
        """Build a string of relevant Solidity source for LLM context."""
        parts = []
        src = self.repo_path / "src"
        if not src.exists():
            src = self.repo_path
        for path in sorted(src.rglob("*.sol")):
            if self.config.target_file and path.resolve() != Path(self.config.target_file).resolve():
                continue
            try:
                content = path.read_text()
                if len(content) > max_chars_per_file:
                    content = content[:max_chars_per_file] + "\n// ... truncated"
                parts.append(f"=== {path.relative_to(self.repo_path)} ===\n{content}")
            except Exception as e:
                parts.append(f"=== {path} (read error: {e}) ===\n")
        return "\n\n".join(parts) if parts else "No Solidity files found."

    def run(self) -> AuditResult:
        result = AuditResult()
        cwd = self.repo_path

        # 1) Run Slither
        logger.info("Stage 1/3: Running Slither...")
        try:
            if self.config.target_file:
                target = Path(self.config.target_file).resolve()
                logger.info("  Target: %s", target.name)
                findings = self.slither_runner.run_slither_file(
                    target,
                    output_path=str(cwd / self.config.slither_output_path),
                    cwd=cwd,
                )
            else:
                logger.info("  Target: repository %s", cwd)
                findings = self.slither_runner.run_slither_repo(
                    cwd,
                    output_path=str(cwd / self.config.slither_output_path),
                    cwd=cwd,
                )
        except Exception as e:
            result.errors.append(f"Slither run failed: {e}")
            logger.exception("Slither failed")
            return result

        result.findings_raw = findings
        logger.info("  Slither found %d issue(s).", len(findings))
        if not findings:
            logger.info("No findings; audit complete.")
            return result

        logger.info("Stage 2/3: Filtering and verifying findings (tool-augmented agent: ripgrep, shell, Foundry, read/write file)...")
        try:
            filter_model = getattr(self.config, "filter_model", None) or getattr(self.config, "llm_model", "claude-sonnet-4-20250514")
            filter_results = run_filter_agent(
                findings=findings,
                repo_path=cwd,
                foundry_runner=self.foundry_runner,
                model=filter_model,
                api_key=getattr(self.config, "llm_api_key", None),
            )
        except Exception as e:
            result.errors.append(f"Filter agent failed: {e}")
            logger.exception("Filter agent failed")
            return result

        result.filter_results = filter_results
        finding_by_id = {f["id"]: f for f in findings}
        true_ids = [r.finding_id for r in filter_results if r.is_true_positive]
        result.true_positive_findings = [finding_by_id[i] for i in true_ids if i in finding_by_id]
        logger.info("  %d true positive(s) (exploitable), %d false positive(s).", len(result.true_positive_findings), len(findings) - len(result.true_positive_findings))

        # Build report entries from filter results (agent already verified: write test, pass, fix, fail, revert, delete)
        for r in filter_results:
            if not r.is_true_positive:
                continue
            finding = finding_by_id.get(r.finding_id)
            if not finding:
                continue
            try:
                entry = self.llm.generate_report_entry(finding, r.exploit_scenario or "Exploit verified by agent.")
                result.report_entries.append(entry)
            except Exception as e:
                result.errors.append(f"Report entry for {r.finding_id}: {e}")
                logger.warning("    Report entry failed: %s", e)

        # 3) Write markdown report
        logger.info("Stage 3/3: Writing report...")
        if result.report_entries:
            report_path = cwd / self.config.report_output_path
            report_to_markdown(result.report_entries, report_path)
            result.report_markdown_path = report_path
            logger.info("  Report written to %s", report_path)
        else:
            logger.info("  No report entries to write.")

        logger.info("Audit complete.")
        return result
