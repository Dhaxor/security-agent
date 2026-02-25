import os
import json
import shutil
import subprocess
import re
from pathlib import Path

class SlitherRunner: 

  def run_slither_repo(self, path, output_path="output.json"): 
    cmd = ["slither", path, "--json", output_path]
    return self._run_slither(cmd, output_path)    

  def run_slither_file(self, path, output_path="output.json", solidity_version=None):
    version = solidity_version or self._extract_solidity_version(path)
    solc_path = self._resolve_solc(version)
    cmd = ["slither", path, "--solc", solc_path, "--json", output_path]

    return self._run_slither(cmd, output_path)


  def _run_slither(self, cmd, output_path):
    report_path = Path(output_path)
    if report_path.exists():
      report_path.unlink()

    # check==False because Slither can return non-zero when detectors find issues even if JSON output succeeded.
    result = subprocess.run(cmd, check=False)

    if result.returncode == 0:
      return

    # Slither can return non-zero when detectors find issues even if JSON output succeeded.
    if report_path.exists():
      try:
        report = json.loads(report_path.read_text())
        if report.get("success") is True:
          return
      except (OSError, ValueError):
        pass

    raise subprocess.CalledProcessError(result.returncode, cmd)        

  def _solc_artifacts_dirs(self) -> list[Path]:
    dirs = []
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
      dirs.append(Path(venv) / ".solc-select" / "artifacts")

    local_venv = Path.cwd() / ".venv"
    dirs.append(local_venv / ".solc-select" / "artifacts")
    dirs.append(Path.home() / ".solc-select" / "artifacts")

    # Preserve order while de-duplicating.
    unique_dirs = []
    for directory in dirs:
      if directory not in unique_dirs:
        unique_dirs.append(directory)
    return unique_dirs

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

    subprocess.run([solc_select, "install", version], check=True, env=install_env)

    for artifacts_dir in self._solc_artifacts_dirs():
      binary_path = artifacts_dir / relative_binary_path
      if binary_path.exists():
        return str(binary_path)

    checked_dirs = ", ".join(str(path) for path in self._solc_artifacts_dirs())
    raise RuntimeError(
      f"solc {version} was not installed by solc-select. Checked: {checked_dirs}"
    )

  def _extract_solidity_version(self, path: str) -> str:
    source = Path(path).read_text()
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    if not match:
      raise RuntimeError("Could not find pragma solidity version in source file.")
    return match.group(1).strip()
      