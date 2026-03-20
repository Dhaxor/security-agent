"""Build AuditConfig from CLI or programmatic options."""

from pathlib import Path

from tools.execution.base import ExecutionEnvironment
from tools.execution.local import LocalExecutionEnvironment
from tools.execution.docker import DockerExecutionEnvironment
from agent.llm.base import LLMClient
from agent.llm.llm_client import AnthropicLiteLLMClient
from agent.audit_agent import AuditConfig
from context.context_manager import ContextConfig


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


def infer_provider(model: str) -> str:
    """Infer the LLM provider from model name."""
    if "/" in model:
        return model.split("/")[0]
    if model.startswith("gpt-") or model.startswith("o1") or model.startswith("o3"):
        return "openai"
    return "anthropic"


def make_context_config(
    max_tokens: int = 30000,
    include_git: bool = True,
    include_call_graph: bool = True,
    include_data_flows: bool = True,
) -> ContextConfig:
    """Create context configuration."""
    return ContextConfig(
        max_tokens=max_tokens,
        include_git_context=include_git,
        include_call_graph=include_call_graph,
        include_data_flows=include_data_flows,
    )


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
    max_context_tokens: int = 30000,
    include_git_context: bool = True,
    include_call_graph: bool = True,
    include_data_flows: bool = True,
) -> AuditConfig:
    repo_path = Path(repo_path).resolve()
    target = Path(target_file).resolve() if target_file else None
    
    context_config = make_context_config(
        max_tokens=max_context_tokens,
        include_git=include_git_context,
        include_call_graph=include_call_graph,
        include_data_flows=include_data_flows,
    )
    
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
        context_config=context_config,
    )
