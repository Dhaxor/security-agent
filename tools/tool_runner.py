from tools.slither_runner import SlitherRunner

class ToolRunner:

  def __init__(self):
    self._slither_runner = SlitherRunner()

  def run_slither_repo(self, path, output_path="parsed_output.json"):
    return self._slither_runner.run_slither_repo(path, output_path)

  def run_slither_file(self, path, output_path="parsed_output.json", solidity_version=None):
    return self._slither_runner.run_slither_file(path, output_path, solidity_version)

  