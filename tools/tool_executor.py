import subprocess

class ToolExecutor:

  def run(self, command, check=True, env=None):
    result = subprocess.run(
      command,
      check=check,
      env=env,
      capture_output=True
    )
    return result