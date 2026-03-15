import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from tools.execution.base import ExecutionEnvironment, RunResult
from tools.slither.slither_parser import SlitherParser


class SlitherRunner:
    def __init__(self, executor: ExecutionEnvironment | None = None):
        from tools.execution.local import LocalExecutionEnvironment

        self.executor = executor or LocalExecutionEnvironment()
        self.slither_parser = SlitherParser()

    def run_slither_repo(
        self,
        path: str | Path,
        output_path: str = "parsed_output.json",
        cwd: Path | None = None,
    ) -> list[dict]:
        path = Path(path)
        cwd = Path(cwd or (path.parent if path.is_file() else path))
        return self._run_slither(str(path), None, output_path, cwd)

    def run_slither_file(
        self,
        path: str | Path,
        output_path: str = "parsed_output.json",
        solidity_version: str | None = None,
        solc_path_override: str | None = None,
        cwd: Path | None = None,
    ) -> list[dict]:
        path = Path(path)
        cwd = Path(cwd or path.parent)
        solc_path = solc_path_override
        if not solc_path:
            version = solidity_version or self._extract_solidity_version(path)
            solc_path = self._resolve_solc(version, cwd)
        return self._run_slither(str(path), solc_path, output_path, cwd)

    def _run_slither(
        self,
        target: str,
        solc_path: str | None,
        output_path: str,
        cwd: Path,
    ) -> list[dict]:
        # Prefer stdout (--json -) so we don't rely on file paths when using Docker.
        cmd = ["slither", target, "--json", "-"]
        if solc_path:
            cmd = ["slither", target, "--solc", solc_path, "--json", "-"]
        result = self.executor.run(cmd, cwd=cwd)

        raw = result.stdout_str.strip()

        try:
            report = json.loads(raw)
        except (TypeError, ValueError) as error:
            raise RuntimeError(
                f"Failed to parse Slither JSON. First 500 chars: {raw[:500]!r} stderr: {result.stderr_str[:300]!r}"
            ) from error

        normalized = self.slither_parser.parse_report(report, str(cwd / output_path))
        if result.returncode == 0 or report.get("success") is True:
            return normalized

        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            output=result.stdout,
            stderr=result.stderr,
        )

    def _solc_artifacts_dirs(self, cwd: Path) -> list[Path]:
        dirs = []
        venv = os.environ.get("VIRTUAL_ENV")
        if venv:
            dirs.append(Path(venv) / ".solc-select" / "artifacts")
        local_venv = cwd / ".venv"
        dirs.append(local_venv / ".solc-select" / "artifacts")
        dirs.append(Path.home() / ".solc-select" / "artifacts")
        unique_dirs = []
        for directory in dirs:
            if directory not in unique_dirs:
                unique_dirs.append(directory)
        return unique_dirs

    def _resolve_solc(self, solidity_version: str, cwd: Path) -> str:
        match = re.search(r"(\d+\.\d+\.\d+)", solidity_version)
        if not match:
            raise RuntimeError(f"Invalid solidity version: {solidity_version}")

        version = match.group(1)
        solc_select = shutil.which("solc-select")
        if not solc_select:
            raise RuntimeError("solc-select is not installed or not found in PATH.")

        binary_name = f"solc-{version}"
        relative_binary_path = Path(binary_name) / binary_name

        for artifacts_dir in self._solc_artifacts_dirs(cwd):
            binary_path = artifacts_dir / relative_binary_path
            if binary_path.exists():
                return str(binary_path)

        install_env = os.environ.copy()
        local_venv = cwd / ".venv"
        if local_venv.exists():
            install_env["VIRTUAL_ENV"] = str(local_venv)
            install_env["PATH"] = f"{local_venv / 'bin'}:{install_env.get('PATH', '')}"

        run = self.executor.run(
            [solc_select, "install", version],
            cwd=cwd,
        )
        if not run.success:
            raise RuntimeError(
                f"solc-select install {version} failed: {run.stderr_str}"
            )

        for artifacts_dir in self._solc_artifacts_dirs(cwd):
            binary_path = artifacts_dir / relative_binary_path
            if binary_path.exists():
                return str(binary_path)

        checked_dirs = ", ".join(str(p) for p in self._solc_artifacts_dirs(cwd))
        raise RuntimeError(
            f"solc {version} was not installed by solc-select. Checked: {checked_dirs}"
        )

    def _extract_solidity_version(self, path: Path) -> str:
        source = path.read_text()
        match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        if not match:
            raise RuntimeError("Could not find pragma solidity version in source file.")
        return match.group(1).strip()
