import subprocess
from pathlib import Path

from tools.execution.base import ExecutionEnvironment, RunResult


class DockerExecutionEnvironment(ExecutionEnvironment):
    """
    Runs commands inside a Docker container with the given image.
    Binds cwd (or a given path) into the container so tools can see the project.
    """

    def __init__(
        self,
        image: str,
        work_dir_in_container: str = "/src",
    ):
        """
        Args:
            image: Docker image to use (e.g. "trailofbits/eth-security-toolbox").
            work_dir_in_container: Path inside the container where the project is mounted.
        """
        self.image = image
        self.work_dir_in_container = work_dir_in_container

    def run(
        self,
        command: list[str],
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        cwd = cwd or Path.cwd()
        cwd = cwd.resolve()
        # Build docker run: mount cwd, set workdir, run command
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{cwd}:{self.work_dir_in_container}",
            "-w",
            self.work_dir_in_container,
            self.image,
        ]
        if env:
            for k, v in env.items():
                docker_cmd.extend(["-e", f"{k}={v}"])
        docker_cmd.extend(command)
        result = subprocess.run(docker_cmd, capture_output=True, cwd=str(cwd))
        return RunResult(
            returncode=result.returncode,
            stdout=result.stdout or b"",
            stderr=result.stderr or b"",
        )
