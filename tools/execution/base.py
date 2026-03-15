from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunResult:
    """Result of running a command in an execution environment."""

    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def stdout_str(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    @property
    def stderr_str(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")

    @property
    def success(self) -> bool:
        return self.returncode == 0


class ExecutionEnvironment(ABC):
    """Abstract interface for running commands (e.g. Slither, Foundry) locally or in Docker."""

    @abstractmethod
    def run(
        self,
        command: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        """
        Run a command in this environment.

        Args:
            command: Command and arguments as a list (e.g. ["slither", ".", "--json", "-"]).
            cwd: Working directory. For Docker, this is typically mounted and used as the working dir.
            env: Optional environment variables.

        Returns:
            RunResult with returncode, stdout, stderr.
        """
        pass
