from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class FilterResult:
    """Result of LLM classifying a single finding as true positive (exploitable) or false positive."""

    finding_id: str
    is_true_positive: bool
    reason: str  # Short explanation why TP or FP
    exploit_scenario: str = ""  # For TPs: description of exploit (from agent verification workflow)


@dataclass
class ExploitTestResult:
    """Generated Foundry test that exploits a vulnerability."""

    finding_id: str
    test_file_path: str  # e.g. "test/Exploit_Suicidal.t.sol"
    test_code: str  # Full Solidity test contract content
    exploit_scenario: str  # Human-readable description of the exploit


@dataclass
class BugReportEntry:
    """Single bug entry for the markdown report."""

    finding_id: str
    severity: str
    type: str  # check_type from Slither
    difficulty: str  # e.g. "Low", "Medium", "High"
    description: str
    exploit_scenario: str
    recommendations: str


class LLMClient(ABC):
    """Abstract interface for the audit LLM (filter findings, generate exploit tests, report content)."""

    @abstractmethod
    def filter_findings(
        self,
        findings: list[dict],
        repo_context: str | None,
    ) -> list[FilterResult]:
        """
        Classify each finding as true positive (exploitable) or false positive.
        Only findings that can be exploited should be marked as true positive.
        """
        pass

    @abstractmethod
    def generate_exploit_test(
        self,
        finding: dict,
        existing_sources: str,
    ) -> ExploitTestResult:
        """Generate a Foundry unit test that exploits the vulnerability."""
        pass

    @abstractmethod
    def generate_fix_patch(
        self,
        finding: dict,
        source_code: str,
    ) -> str:
        """Generate a temporary fix (patch) for the vulnerable code. Used to verify test fails before fix."""
        pass

    @abstractmethod
    def generate_report_entry(
        self,
        finding: dict,
        exploit_scenario: str,
    ) -> BugReportEntry:
        """Generate one report entry (severity, type, difficulty, description, exploit scenario, recommendations)."""
        pass
