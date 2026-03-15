"""Build AuditConfig from CLI or programmatic options."""

from pathlib import Path

from tools.execution.base import ExecutionEnvironment
from tools.execution.local import LocalExecutionEnvironment
from tools.execution.docker import DockerExecutionEnvironment
from agent.llm.base import LLMClient
from agent.llm.anthropic_litellm import AnthropicLiteLLMClient
from agent.audit_agent import AuditConfig


def make_execution_env(
    use_docker: bool = False,
    docker_image: str | None = None,
) -> ExecutionEnvironment:
    if use_docker:
        image = docker_image or "trailofbits/eth-security-toolbox"
        return DockerExecutionEnvironment(image=image)
    return LocalExecutionEnvironment()


def make_llm_client(
    model: str = "claude-sonnet-4-20250514",
    api_key: str | None = None,
) -> LLMClient:
    return AnthropicLiteLLMClient(model=model, api_key=api_key)


def make_audit_config(
    repo_path: Path | str,
    target_file: Path | str | None = None,
    *,
    slither_output: str = "slither_findings.json",
    report_output: str = "audit_report.md",
    use_docker: bool = False,
    docker_image: str | None = None,
    model: str = "claude-sonnet-4-20250514",
    api_key: str | None = None,
    filter_model: str | None = None,
) -> AuditConfig:
    repo_path = Path(repo_path).resolve()
    target = Path(target_file).resolve() if target_file else None
    return AuditConfig(
        repo_path=repo_path,
        target_file=target,
        slither_output_path=slither_output,
        report_output_path=report_output,
        execution_env=make_execution_env(use_docker=use_docker, docker_image=docker_image),
        llm_client=make_llm_client(model=model, api_key=api_key),
        llm_model=model,
        llm_api_key=api_key,
        filter_model=filter_model,
    )
