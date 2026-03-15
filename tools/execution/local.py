import subprocess
from pathlib import Path

from tools.execution.base import ExecutionEnvironment, RunResult


class LocalExecutionEnvironment(ExecutionEnvironment):
    """Runs commands locally via subprocess."""

    def run(
        self,
        command: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        kwargs = {"capture_output": True}
        if cwd is not None:
            kwargs["cwd"] = str(cwd)
        if env is not None:
            kwargs["env"] = env
        result = subprocess.run(command, **kwargs)
        return RunResult(
            returncode=result.returncode,
            stdout=result.stdout or b"",
            stderr=result.stderr or b"",
        )
