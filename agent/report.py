"""Markdown report generation for audit findings."""

from pathlib import Path

from agent.llm.base import BugReportEntry


def _ensure_str(value: str | list) -> str:
    """Convert a field to str; if it's a list (e.g. from LLM JSON), join as newlines."""
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value) if value is not None else ""


def report_to_markdown(entries: list[BugReportEntry], output_path: Path | str) -> None:
    """Write a markdown report for the given bug report entries."""
    output_path = Path(output_path)
    lines = [
        "# Solidity Security Audit Report",
        "",
        "This report lists confirmed vulnerabilities (true positives) that were verified with exploit tests.",
        "",
        "---",
        "",
    ]
    for i, entry in enumerate(entries, 1):
        lines.extend([
            f"## {i}. {_ensure_str(entry.type)}",
            "",
            f"- **Severity:** {_ensure_str(entry.severity)}",
            f"- **Type:** {_ensure_str(entry.type)}",
            f"- **Difficulty:** {_ensure_str(entry.difficulty)}",
            "",
            "### Description",
            "",
            _ensure_str(entry.description),
            "",
            "### Exploit Scenario",
            "",
            _ensure_str(entry.exploit_scenario),
            "",
            "### Recommendations",
            "",
            _ensure_str(entry.recommendations),
            "",
            "---",
            "",
        ])
    output_path.write_text("\n".join(lines), encoding="utf-8")
