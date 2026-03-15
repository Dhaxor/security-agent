"""
Anthropic LLM client via LiteLLM for the Solidity auditing agent.
"""

import json
import logging
import re
from typing import Any

import litellm

# Suppress LiteLLM's internal logging (INFO/DEBUG)
logging.getLogger("litellm").setLevel(logging.WARNING)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)

from agent.llm.base import (
    LLMClient,
    FilterResult,
    ExploitTestResult,
    BugReportEntry,
)


def _model_id(model: str) -> str:
    """Normalize to litellm model string (e.g. anthropic/claude-3-5-sonnet)."""
    if model.startswith("anthropic/"):
        return model
    return f"anthropic/{model}"


def _extract_json(raw: str) -> str:
    """Extract a JSON object from LLM output that may include markdown or prose."""
    raw = raw.strip()
    # Markdown code block: ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
    if match:
        return match.group(1).strip()
    # First top-level { ... }
    start = raw.find("{")
    if start == -1:
        return raw
    depth = 0
    for i, c in enumerate(raw[start:], start=start):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return raw[start : i + 1]
    return raw


def _extract_fenced_code(raw: str, lang: str = "solidity") -> str:
    """Extract content from a fenced code block (e.g. ```solidity ... ``` or ``` ... ```)."""
    # Prefer ```solidity then any ```
    for pattern in (rf"```(?:{re.escape(lang)})?\s*\n(.*?)```", r"```\s*\n(.*?)```"):
        match = re.search(pattern, raw, re.DOTALL)
        if match:
            return match.group(1).strip()
    return ""


class AnthropicLiteLLMClient(LLMClient):
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str | None = None,
    ):
        self.model = _model_id(model)
        if api_key:
            litellm.anthropic_key = api_key

    def _complete(
        self,
        system: str,
        user: str,
        response_format: dict[str, str] | None = None,
    ) -> str:
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if response_format is not None:
            kwargs["response_format"] = response_format
        response = litellm.completion(**kwargs)
        return response.choices[0].message.content or ""

    def filter_findings(
        self,
        findings: list[dict],
        repo_context: str | None,
    ) -> list[FilterResult]:
        system = """You are a Solidity security auditor. You receive a list of static analysis findings (from Slither) and must classify each as TRUE POSITIVE (exploitable bug) or FALSE POSITIVE.

Rules:
- Only mark a finding as TRUE POSITIVE if it describes a vulnerability that can be exploited with a concrete Foundry test (e.g. unauthorized access, fund theft, denial of service, logic error that can be demonstrated).
- Mark as FALSE POSITIVE: informational only (e.g. solc-version), style issues, or issues that cannot be meaningfully exploited in a unit test.
- Respond with a JSON object: { "results": [ { "finding_id": "<id>", "is_true_positive": true|false, "reason": "<short explanation>" }, ... ] }
- Use the exact "id" field from each finding for finding_id."""

        user = f"Repo context (optional):\n{repo_context or 'N/A'}\n\nFindings (JSON):\n{json.dumps(findings, indent=2)}"
        raw = self._complete(system, user, response_format={"type": "json_object"})
        data = json.loads(_extract_json(raw))
        results = []
        for r in data.get("results", []):
            results.append(
                FilterResult(
                    finding_id=r.get("finding_id", ""),
                    is_true_positive=bool(r.get("is_true_positive", False)),
                    reason=r.get("reason", ""),
                )
            )
        return results

    def generate_exploit_test(
        self,
        finding: dict,
        existing_sources: str,
    ) -> ExploitTestResult:
        system = """You are a Solidity security expert. Given a single Slither finding that was classified as a true positive, write a Foundry (Solidity) unit test that EXPLOITS the vulnerability.

Requirements:
- Output a complete Solidity test file that can be placed in the project's test directory (e.g. test/).
- Use Foundry's test style: contract ending in Test, functions starting with test.
- The test must demonstrate the bug: e.g. call the vulnerable function and assert an undesired outcome (e.g. attacker gains funds, contract is destroyed, access control bypass).
- If the finding involves a specific contract/function, deploy or use that contract in the test and trigger the vulnerable code path.

Response format (use exactly this structure):
1. A JSON object with only: "test_file_path" (e.g. "test/Exploit_Suicidal.t.sol") and "exploit_scenario" (1-3 sentence description). No other fields.
2. Then a fenced code block with the full Solidity test code, e.g.:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// ... rest of test
```

Do not put the Solidity code inside the JSON. Put the JSON first, then the code in a ```solidity ... ``` block."""

        user = f"Finding:\n{json.dumps(finding, indent=2)}\n\nRelevant repo/source context:\n{existing_sources}"
        raw = self._complete(system, user, response_format={"type": "json_object"})
        json_str = _extract_json(raw)
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Model may have embedded code in JSON; use part before first fenced block and extract code from block
            pre = raw.split("```")[0]
            try:
                data = json.loads(_extract_json(pre))
            except json.JSONDecodeError:
                data = {}
        test_code = _extract_fenced_code(raw)
        if not test_code and "test_code" in data:
            # Fallback: model put code in JSON
            test_code = data.get("test_code", "")
            if "\\n" in test_code and "\n" not in test_code:
                test_code = test_code.replace("\\n", "\n").replace('\\"', '"')
        results = ExploitTestResult(
            finding_id=finding.get("id", ""),
            test_file_path=data.get("test_file_path", "test/Exploit.t.sol"),
            test_code=test_code,
            exploit_scenario=data.get("exploit_scenario", ""),
        )
        return results

    def generate_fix_patch(
        self,
        finding: dict,
        source_code: str,
    ) -> str:
        system = """You are a Solidity security expert. Given a vulnerability finding and the full source code of the affected file, output a FIXED version of the source code that mitigates the vulnerability.

- Return ONLY the full fixed Solidity source code, no explanation before or after.
- Preserve formatting and structure; only change what is necessary to fix the bug.
- Do not add comments like "// FIXED" unless the user asked for it."""

        user = f"Finding:\n{json.dumps(finding, indent=2)}\n\nSource code to fix:\n{source_code}"
        return self._complete(system, user).strip()

    def generate_report_entry(
        self,
        finding: dict,
        exploit_scenario: str,
    ) -> BugReportEntry:
        system = """You are a Solidity security auditor writing a report. For the given finding and its exploit scenario, produce a structured report entry in JSON:

{
  "severity": "Critical|High|Medium|Low|Informational",
  "type": "<check type from finding>",
  "difficulty": "Low|Medium|High",
  "description": "<clear 1-3 sentence description of the vulnerability>",
  "exploit_scenario": "<same or refined exploit scenario>",
  "recommendations": "<concrete fix recommendations, bullet points OK>"
}

Use the finding's severity if appropriate; set difficulty based on how hard the bug is to exploit."""

        user = f"Finding:\n{json.dumps(finding, indent=2)}\n\nExploit scenario:\n{exploit_scenario}"
        raw = self._complete(system, user, response_format={"type": "json_object"})
        data = json.loads(_extract_json(raw))

        def _str_field(v: Any, default: str = "") -> str:
            if v is None or (isinstance(v, list) and len(v) == 0):
                return default
            if isinstance(v, list):
                return "\n".join(str(x) for x in v)
            return str(v)

        return BugReportEntry(
            finding_id=finding.get("id", ""),
            severity=_str_field(data.get("severity"), finding.get("severity", "Unknown")),
            type=_str_field(data.get("type"), finding.get("check_type", "Unknown")),
            difficulty=_str_field(data.get("difficulty"), "Medium"),
            description=_str_field(data.get("description"), finding.get("description", "")),
            exploit_scenario=_str_field(data.get("exploit_scenario"), exploit_scenario),
            recommendations=_str_field(data.get("recommendations"), ""),
        )
