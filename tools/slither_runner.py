import os
import json
import shutil
import subprocess
import re
from pathlib import Path
from tools.tool_executor import ToolExecutor
from tools.slither_parser import SlitherParser

class SlitherRunner: 

  def __init__(self):
    self.tool_executor = ToolExecutor()
    self.slither_parser = SlitherParser()

  # runs slither on a repo
  def run_slither_repo(self, path, output_path="parsed_output.json"): 
    cmd = ["slither", path, "--json", "-"]
    return self._run_slither(cmd, output_path)    

  # runs slither on a file
  def run_slither_file(self, path, output_path="parsed_output.json", solidity_version=None):
    version = solidity_version or self._extract_solidity_version(path)
    solc_path = self._resolve_solc(version)
    cmd = ["slither", path, "--solc", solc_path, "--json", "-"]

    return self._run_slither(cmd, output_path)

  # runs slither
  def _run_slither(self, cmd, output_path):
    # check==False because Slither can return non-zero when detectors find issues even if JSON output succeeded.
    result = self.tool_executor.run(cmd, False)
    try:
      report = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
      raise RuntimeError(
        f"Failed to parse Slither JSON output from stdout. stderr: {result.stderr!r}"
      ) from error

    normalized = self.slither_parser.parse_report(report, output_path)
    if result.returncode == 0 or report.get("success") is True:
      return normalized

    raise subprocess.CalledProcessError(
      result.returncode,
      cmd,
      output=result.stdout,
      stderr=result.stderr,
    )

  # returns the .solc-select directory for virtual environment and global
  def _solc_artifacts_dirs(self) -> list[Path]:
    dirs = []
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
      dirs.append(Path(venv) / ".solc-select" / "artifacts") # virtual environment

    local_venv = Path.cwd() / ".venv"
    dirs.append(local_venv / ".solc-select" / "artifacts") # local environment
    dirs.append(Path.home() / ".solc-select" / "artifacts") # global

    # Preserve order while de-duplicating.
    unique_dirs = []
    for directory in dirs:
      if directory not in unique_dirs:
        unique_dirs.append(directory)
    return unique_dirs

  # returns file path for solidity_version compiler
  # first finds it, and if it is not available, it installs it.
  def _resolve_solc(self, solidity_version: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", solidity_version)
    if not match:
      raise RuntimeError(f"Invalid solidity version: {solidity_version}")

    version = match.group(1)
    solc_select = shutil.which("solc-select")
    if not solc_select:
      raise RuntimeError("solc-select is not installed or not found in PATH.")

    binary_name = f"solc-{version}"
    relative_binary_path = Path(binary_name) / binary_name

    for artifacts_dir in self._solc_artifacts_dirs():
      binary_path = artifacts_dir / relative_binary_path
      if binary_path.exists():
        return str(binary_path)

    # Prefer installing into the project-local .venv when available.
    install_env = os.environ.copy()
    local_venv = Path.cwd() / ".venv"
    if local_venv.exists():
      install_env["VIRTUAL_ENV"] = str(local_venv)
      install_env["PATH"] = f"{local_venv / 'bin'}:{install_env.get('PATH', '')}"

    self.tool_executor.run([solc_select, "install", version], check=True, env=install_env)

    for artifacts_dir in self._solc_artifacts_dirs():
      binary_path = artifacts_dir / relative_binary_path
      if binary_path.exists():
        return str(binary_path)

    checked_dirs = ", ".join(str(path) for path in self._solc_artifacts_dirs())
    raise RuntimeError(
      f"solc {version} was not installed by solc-select. Checked: {checked_dirs}"
    )

  # extracts solidity version from solidity file
  def _extract_solidity_version(self, path: str) -> str:
    source = Path(path).read_text()
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if not match:
      raise RuntimeError("Could not find pragma solidity version in source file.")
    return match.group(1).strip()
      