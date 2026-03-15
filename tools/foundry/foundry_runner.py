from pathlib import Path

from tools.execution.base import ExecutionEnvironment, RunResult


class FoundryRunner:
    """Runs Foundry (forge) commands in a given execution environment (local or Docker)."""

    def __init__(self, executor: ExecutionEnvironment):
        self.executor = executor

    def test(
        self,
        cwd: Path | None = None,
        match_path: str | None = None,
        match_contract: str | None = None,
    ) -> RunResult:
        """
        Run `forge test`.

        Args:
            cwd: Project root (directory containing foundry.toml or src/).
            match_path: Optional filter by test file path (e.g. "test/Exploit.t.sol").
            match_contract: Optional filter by contract name (e.g. "ExploitTest").

        Returns:
            RunResult with returncode, stdout, stderr.
        """
        cmd = ["forge", "test"]
        if match_path:
            cmd.extend(["--match-path", match_path])
        if match_contract:
            cmd.extend(["--match-contract", match_contract])
        cwd = cwd or Path.cwd()
        return self.executor.run(cmd, cwd=cwd)

    def build(self, cwd: Path | None = None) -> RunResult:
        """Run `forge build`."""
        cwd = cwd or Path.cwd()
        return self.executor.run(["forge", "build"], cwd=cwd)
