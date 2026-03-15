"""
Tools the filter agent can use: ripgrep, shell, foundry (build/test), and submit_true_positives.
All run in the repository directory (cwd).
"""

import json
import logging
import subprocess
from pathlib import Path

from tools.execution.base import ExecutionEnvironment, RunResult
from tools.foundry.foundry_runner import FoundryRunner

logger = logging.getLogger(__name__)

# Max characters returned per tool to keep context size bounded (output may be truncated).
MAX_TOOL_OUTPUT_CHARS = 4000

# OpenAI-style tool definitions for LiteLLM
FILTER_AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_finding_detail",
            "description": "Get the full JSON for one Slither finding by id. Use this when you need to analyze a finding in detail (e.g. location, raw_tool_output).",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The 'id' of the finding from the summary list.",
                    },
                },
                "required": ["finding_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ripgrep",
            "description": "Search for a pattern in the repository using ripgrep (rg). Use to find usages of functions, contract names, or code patterns in Solidity and other files. Returns matching lines with file paths and line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "The search pattern (regex or literal string). Escape special regex chars if needed.",
                    },
                    "glob": {
                        "type": "string",
                        "description": "Optional glob to restrict files, e.g. '*.sol' for Solidity only.",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell",
            "description": "Run a shell command in the repository root. Use for reading files (cat, head), listing (ls, find), deleting files (rm), or any command that helps inspect or modify the codebase. Command runs with cwd=repo root. Use 'rm <path>' to delete the exploit test file after verification.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to run (e.g. 'cat src/Contract.sol', 'rm test/Exploit.t.sol').",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the full contents of a file in the repository. Path is relative to the repo root (e.g. 'src/Contract.sol', 'test/Exploit.t.sol'). Use to read source before writing a fix or to inspect test files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file relative to the repository root.",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file in the repository. Path is relative to the repo root. Creates parent directories if needed. Use to write your exploit test file, to apply the fix to the vulnerable source, and to revert the fix by writing back the original content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file relative to the repository root (e.g. 'test/Exploit_Suicidal.t.sol', 'src/Vault.sol').",
                    },
                    "content": {
                        "type": "string",
                        "description": "Full file content to write.",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "foundry_build",
            "description": "Run 'forge build' in the repository. Use to check if the project compiles.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "foundry_test",
            "description": "Run 'forge test' in the repository. Optionally filter by test path or contract name. Use to run existing tests or to verify a new test file you've created (e.g. after writing an exploit test to a file).",
            "parameters": {
                "type": "object",
                "properties": {
                    "match_path": {
                        "type": "string",
                        "description": "Optional: run only tests in files matching this path, e.g. 'test/Exploit.t.sol'.",
                    },
                    "match_contract": {
                        "type": "string",
                        "description": "Optional: run only tests in the contract with this name.",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_true_positives",
            "description": "Call this ONLY when you have finished verifying ALL true positives. For each finding you submit, you MUST have completed the full verification: write exploit test, run test (pass), apply fix, run test (fail), revert fix, delete test file. Submit the list of finding IDs and an exploit_scenario for each.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of finding 'id' values that are true positives and that you verified with the full workflow.",
                    },
                    "reasons": {
                        "type": "object",
                        "description": "Optional: short reason per finding_id.",
                    },
                    "exploit_scenarios": {
                        "type": "object",
                        "description": "For each finding_id, provide a 1-3 sentence description of how the exploit works (e.g. 'Attacker calls withdraw() without authentication, draining the contract.'). Keys are finding IDs, values are strings. Should include an entry for every finding in finding_ids.",
                    },
                },
                "required": ["finding_ids"],
            },
        },
    },
]


def _truncate(text: str, max_chars: int, suffix: str = "\n... (output truncated)") -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - len(suffix)] + suffix


class AgentToolExecutor:
    """Executes filter-agent tools in the repo directory. Uses the same ExecutionEnvironment as Foundry so shell/ripgrep run in Docker when --docker is used."""

    def __init__(
        self,
        repo_path: Path,
        foundry_runner: FoundryRunner,
        execution_env: ExecutionEnvironment | None = None,
        shell_timeout_seconds: int = 30,
        max_output_chars: int = MAX_TOOL_OUTPUT_CHARS,
        findings_by_id: dict[str, dict] | None = None,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.foundry_runner = foundry_runner
        self.execution_env = execution_env or foundry_runner.executor
        self.shell_timeout = shell_timeout_seconds
        self.max_output_chars = max_output_chars
        self.findings_by_id = findings_by_id or {}
        self._foundry_build_cache: str | None = None

    def run(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool and return a string result for the LLM."""
        if tool_name == "get_finding_detail":
            return self._get_finding_detail(arguments.get("finding_id", ""))
        if tool_name == "ripgrep":
            return self._ripgrep(
                arguments.get("pattern", ""),
                arguments.get("glob"),
            )
        if tool_name == "shell":
            return self._shell(arguments.get("command", ""))
        if tool_name == "read_file":
            return self._read_file(arguments.get("path", ""))
        if tool_name == "write_file":
            return self._write_file(
                arguments.get("path", ""),
                arguments.get("content", ""),
            )
        if tool_name == "foundry_build":
            return self._foundry_build()
        if tool_name == "foundry_test":
            return self._foundry_test(
                arguments.get("match_path"),
                arguments.get("match_contract"),
            )
        if tool_name == "submit_true_positives":
            return self._submit_true_positives(
                arguments.get("finding_ids", []),
                arguments.get("reasons"),
                arguments.get("exploit_scenarios"),
            )
        return f"Unknown tool: {tool_name}"

    def _get_finding_detail(self, finding_id: str) -> str:
        if not finding_id:
            return "Error: finding_id is required."
        finding = self.findings_by_id.get(finding_id)
        if not finding:
            return f"Error: no finding with id {finding_id!r}."
        return json.dumps(finding, indent=2)

    def warm_foundry_build_cache(self) -> None:
        """Run forge build once and cache the result for foundry_build tool."""
        if self._foundry_build_cache is not None:
            return
        r = self.foundry_runner.build(cwd=self.repo_path)
        if r.success:
            self._foundry_build_cache = "forge build succeeded."
        else:
            self._foundry_build_cache = _truncate(
                f"forge build failed (exit {r.returncode}):\n{r.stderr_str}",
                self.max_output_chars,
            )

    def _ripgrep(self, pattern: str, glob: str | None) -> str:
        if not pattern:
            return "Error: pattern is required."
        cmd = ["rg", "--no-heading", "--line-number", "--color", "never", pattern]
        if glob:
            cmd.extend(["--glob", glob])
        cmd.append(".")  # search in cwd (repo); executor sets cwd
        try:
            r = self.execution_env.run(cmd, cwd=self.repo_path)
            if r.returncode == 0:
                out = r.stdout_str or "(no matches)"
            elif r.returncode == 1:
                out = "(no matches)"
            else:
                out = f"ripgrep stderr: {r.stderr_str or r.stdout_str or 'error'}"
            return _truncate(out, self.max_output_chars)
        except FileNotFoundError:
            return "Error: ripgrep (rg) is not installed or not in PATH."
        except Exception as e:
            return f"Error: {e}"

    def _read_file(self, path: str) -> str:
        if not path or not path.strip():
            return "Error: path is required."
        p = (self.repo_path / path.strip()).resolve()
        if not p.is_relative_to(self.repo_path):
            return "Error: path must be inside the repository."
        try:
            return _truncate(p.read_text(encoding="utf-8"), self.max_output_chars)
        except FileNotFoundError:
            return f"Error: file not found: {path}"
        except Exception as e:
            return f"Error: {e}"

    def _write_file(self, path: str, content: str) -> str:
        if not path or not path.strip():
            return "Error: path is required."
        p = (self.repo_path / path.strip()).resolve()
        if not p.is_relative_to(self.repo_path):
            return "Error: path must be inside the repository."
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return f"Wrote {path}"
        except Exception as e:
            return f"Error: {e}"

    def _shell(self, command: str) -> str:
        if not command or not command.strip():
            return "Error: command is required."
        try:
            # Run via ExecutionEnvironment so shell runs in Docker when --docker is used.
            # Use sh -c so the command string is executed in the repo cwd.
            r = self.execution_env.run(
                ["sh", "-c", command],
                cwd=self.repo_path,
            )
            out = r.stdout_str or ""
            err = r.stderr_str or ""
            if err:
                out = f"stderr:\n{err}\n\nstdout:\n{out}" if out else f"stderr:\n{err}"
            out = out.strip() or f"(exit code {r.returncode})"
            return _truncate(out, self.max_output_chars)
        except Exception as e:
            return f"Error: {e}"

    def _foundry_build(self) -> str:
        if self._foundry_build_cache is not None:
            return self._foundry_build_cache
        r = self.foundry_runner.build(cwd=self.repo_path)
        if r.success:
            self._foundry_build_cache = "forge build succeeded."
            return self._foundry_build_cache
        self._foundry_build_cache = _truncate(
            f"forge build failed (exit {r.returncode}):\n{r.stderr_str}",
            self.max_output_chars,
        )
        return self._foundry_build_cache

    def _foundry_test(
        self,
        match_path: str | None,
        match_contract: str | None,
    ) -> str:
        r = self.foundry_runner.test(
            cwd=self.repo_path,
            match_path=match_path,
            match_contract=match_contract,
        )
        if r.success:
            out = f"forge test passed.\n{r.stdout_str}"
        else:
            out = f"forge test failed (exit {r.returncode}):\nstdout:\n{r.stdout_str}\nstderr:\n{r.stderr_str}"
        return _truncate(out, self.max_output_chars)

    def _submit_true_positives(
        self,
        finding_ids: list[str],
        reasons: dict | None,
        exploit_scenarios: dict | None = None,
    ) -> str:
        """Special tool: returns a magic payload so the agent loop can parse the result."""
        payload = {
            "finding_ids": finding_ids,
            "reasons": reasons or {},
            "exploit_scenarios": exploit_scenarios or {},
        }
        return "__SUBMIT_TRUE_POSITIVES__" + json.dumps(payload)
