"""
Context Manager: Token-optimized context builder with intelligent prioritization.

Orchestrates semantic graph, call graph, and git context to build optimal
LLM context within token limits. Supports 30k+ input tokens efficiently.
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

from context.semantic_graph import SemanticGraph
from context.call_graph import CallGraph
from context.git_context import GitContext

logger = logging.getLogger(__name__)


class ContextPriority(Enum):
    """Priority levels for context elements."""
    CRITICAL = 1    # Must include (finding location, direct dependencies)
    HIGH = 2        # Should include (call chain, storage access)
    MEDIUM = 3      # Nice to have (related contracts, recent changes)
    LOW = 4         # Background (git history, project structure)


@dataclass
class ContextConfig:
    """Configuration for context building."""
    max_tokens: int = 0  # 0 = unlimited, no artificial cap
    max_chars_per_file: int = 50000  # Max chars per source file
    max_dependencies_depth: int = 5  # How deep to trace dependencies
    max_call_chain_depth: int = 5  # How deep to trace call chains
    include_git_context: bool = True
    include_call_graph: bool = True
    include_data_flows: bool = True
    tokens_per_char: float = 0.25  # Approximate tokens per character
    buffer_tokens: int = 0  # No buffer needed when unlimited


@dataclass
class ContextElement:
    """A single piece of context with metadata."""
    content: str
    priority: ContextPriority
    source: str  # Where this context came from
    token_estimate: int = 0
    relevance_score: float = 0.0  # 0-1, how relevant to the finding

    def __post_init__(self):
        if self.token_estimate == 0:
            self.token_estimate = int(len(self.content) * 0.25)


class ContextManager:
    """
    Orchestrates context building from multiple sources.
    
    Features:
    - Token-aware context assembly
    - Priority-based inclusion
    - Incremental context building
    - Caching for performance
    """

    def __init__(self, repo_path: Path, config: ContextConfig | None = None):
        self.repo_path = Path(repo_path).resolve()
        self.config = config or ContextConfig()

        # Initialize components
        self.semantic_graph = SemanticGraph()
        self.call_graph = CallGraph(self.semantic_graph)
        self.git_context = GitContext(self.repo_path)

        # State
        self._indexed = False
        self._index_time: float = 0

    def index(self):
        """Index the repository for context building."""
        if self._indexed:
            return

        start = time.time()
        logger.info("Indexing repository: %s", self.repo_path)

        # Index semantic graph
        contract_count = self.semantic_graph.index_directory(self.repo_path)
        logger.info("Indexed %d contracts", contract_count)

        # Build call graph
        if self.config.include_call_graph:
            self.call_graph.build()

        self._indexed = True
        self._index_time = time.time() - start
        logger.info("Indexing complete in %.2f seconds", self._index_time)

    def build_context_for_finding(self, finding: dict) -> str:
        """
        Build optimized context for a single Slither finding.
        Returns a string ready for LLM consumption.
        """
        if not self._indexed:
            self.index()

        elements: list[ContextElement] = []

        # 1. Critical: Finding details
        elements.append(self._build_finding_context(finding))

        # 2. Critical: Source code at finding location
        source_context = self._build_source_context(finding)
        if source_context:
            elements.append(source_context)

        # 3. High: Contract context
        contract_context = self._build_contract_context(finding)
        if contract_context:
            elements.extend(contract_context)

        # 4. High: Call chain context
        if self.config.include_call_graph:
            call_context = self._build_call_context(finding)
            if call_context:
                elements.append(call_context)

        # 5. Medium: Data flow context
        if self.config.include_data_flows:
            flow_context = self._build_data_flow_context(finding)
            if flow_context:
                elements.append(flow_context)

        # 6. Medium: Git context
        if self.config.include_git_context:
            git_context = self._build_git_context(finding)
            if git_context:
                elements.append(git_context)

        # 7. Low: Project structure
        structure_context = self._build_structure_context()
        if structure_context:
            elements.append(structure_context)

        # Sort by priority and relevance
        elements.sort(key=lambda e: (e.priority.value, -e.relevance_score))

        # Assemble within token budget
        return self._assemble_context(elements)

    def build_context_for_findings(self, findings: list[dict]) -> dict[str, str]:
        """
        Build context for multiple findings efficiently.
        Returns dict of finding_id -> context string.
        """
        if not self._indexed:
            self.index()

        contexts = {}
        for finding in findings:
            finding_id = finding.get("id", "unknown")
            try:
                contexts[finding_id] = self.build_context_for_finding(finding)
            except Exception as e:
                logger.warning("Failed to build context for finding %s: %s", finding_id, e)
                contexts[finding_id] = f"Error building context: {e}"

        return contexts

    def _build_finding_context(self, finding: dict) -> ContextElement:
        """Build context from the finding itself."""
        parts = [
            f"=== Finding: {finding.get('check_type', 'Unknown')} ===",
            f"Severity: {finding.get('severity', 'Unknown')}",
            f"Confidence: {finding.get('confidence', 'Unknown')}",
            f"Contract: {finding.get('contract', 'Unknown')}",
            f"Function: {finding.get('function', 'Unknown')}",
            f"Description: {finding.get('description', '')[:500]}",
        ]

        location = finding.get("location", {})
        if location.get("file"):
            parts.append(f"File: {location['file']}")
            if location.get("line_start"):
                parts.append(f"Lines: {location['line_start']}-{location.get('line_end', location['line_start'])}")

        return ContextElement(
            content="\n".join(parts),
            priority=ContextPriority.CRITICAL,
            source="finding",
            relevance_score=1.0,
        )

    def _build_source_context(self, finding: dict) -> ContextElement | None:
        """Build context from source code at finding location."""
        location = finding.get("location", {})
        file_path = location.get("file")
        
        if not file_path:
            return None

        full_path = self.repo_path / file_path
        if not full_path.exists():
            # Try finding the file in the repo
            for sol_file in self.repo_path.rglob("*.sol"):
                if sol_file.name == file_path or str(sol_file).endswith(file_path):
                    full_path = sol_file
                    break

        if not full_path.exists():
            return None

        try:
            content = full_path.read_text(encoding="utf-8")
            lines = content.split("\n")
            
            # Get context around the finding
            line_start = location.get("line_start", 1) - 1
            line_end = location.get("line_end", line_start + 1) - 1
            
            # Expand context window
            context_start = max(0, line_start - 20)
            context_end = min(len(lines), line_end + 20)
            
            relevant_lines = lines[context_start:context_end]
            numbered_lines = []
            for i, line in enumerate(relevant_lines, start=context_start + 1):
                marker = ">>>" if context_start <= i - 1 <= context_end else "   "
                numbered_lines.append(f"{marker} {i:4d} | {line}")

            source_content = f"=== Source: {file_path} ===\n" + "\n".join(numbered_lines)

            # Truncate if too long
            if len(source_content) > self.config.max_chars_per_file:
                source_content = source_content[:self.config.max_chars_per_file] + "\n// ... truncated"

            return ContextElement(
                content=source_content,
                priority=ContextPriority.CRITICAL,
                source="source",
                relevance_score=0.95,
            )
        except Exception as e:
            logger.warning("Failed to read source %s: %s", file_path, e)
            return None

    def _build_contract_context(self, finding: dict) -> list[ContextElement]:
        """Build context from contract analysis."""
        elements = []
        contract_name = finding.get("contract", "")

        if not contract_name:
            return elements

        # Get contract from semantic graph
        if contract_name in self.semantic_graph.contracts:
            contract = self.semantic_graph.contracts[contract_name]
            
            # Get dependencies
            deps = self.semantic_graph.get_contract_dependencies(
                contract_name, 
                max_depth=self.config.max_dependencies_depth
            )

            # Build context for main contract
            contract_ctx = self.semantic_graph._format_contract_context(
                contract, 
                finding.get("function", "")
            )
            elements.append(ContextElement(
                content=contract_ctx,
                priority=ContextPriority.CRITICAL,
                source="semantic_graph",
                relevance_score=0.9,
            ))

            # Build context for dependencies
            for dep in sorted(deps):
                if dep in self.semantic_graph.contracts:
                    dep_contract = self.semantic_graph.contracts[dep]
                    dep_ctx = self.semantic_graph._format_contract_context(dep_contract)
                    elements.append(ContextElement(
                        content=dep_ctx,
                        priority=ContextPriority.HIGH,
                        source="dependency",
                        relevance_score=0.7,
                    ))

        return elements

    def _build_call_context(self, finding: dict) -> ContextElement | None:
        """Build context from call graph analysis."""
        contract_name = finding.get("contract", "")
        function_name = finding.get("function", "")

        if not contract_name or not function_name:
            return None

        # Get call chain summary
        call_summary = self.call_graph.get_call_chain_summary(
            contract_name,
            function_name,
            max_depth=self.config.max_call_chain_depth,
        )

        # Check for reentrancy paths
        reentrancy_paths = self.call_graph.find_reentrancy_paths(contract_name)

        # Check for breaking changes
        breaking_changes = self.call_graph.find_breaking_changes(
            contract_name, function_name
        )

        parts = ["=== Call Graph Context ==="]
        parts.append(call_summary)

        if reentrancy_paths:
            parts.append("\nPotential reentrancy paths:")
            for path in reentrancy_paths[:3]:
                parts.append(f"  {' -> '.join(path)}")

        if breaking_changes:
            parts.append("\nBreaking change impact:")
            for change in breaking_changes[:5]:
                parts.append(
                    f"  {change['affected_contract']}.{change['affected_function']} "
                    f"({'external' if change['is_external'] else 'internal'})"
                )

        return ContextElement(
            content="\n".join(parts),
            priority=ContextPriority.HIGH,
            source="call_graph",
            relevance_score=0.8,
        )

    def _build_data_flow_context(self, finding: dict) -> ContextElement | None:
        """Build context from data flow analysis."""
        contract_name = finding.get("contract", "")
        function_name = finding.get("function", "")

        if not contract_name or not function_name:
            return None

        # Get function from semantic graph
        if contract_name in self.semantic_graph.contracts:
            contract = self.semantic_graph.contracts[contract_name]
            if function_name in contract.functions:
                func = contract.functions[function_name]

                parts = ["=== Data Flow Context ==="]
                
                if func.storage_reads:
                    parts.append(f"Reads: {', '.join(func.storage_reads[:10])}")
                
                if func.storage_writes:
                    parts.append(f"Writes: {', '.join(func.storage_writes[:10])}")
                
                # Trace data flows for written variables
                for write_var in func.storage_writes[:3]:
                    flows = self.call_graph.trace_data_flow(write_var, contract_name)
                    if flows:
                        parts.append(f"\nData flow for {write_var}:")
                        for flow in flows[:3]:
                            parts.append(f"  {flow.format()} ({flow.flow_type})")

                return ContextElement(
                    content="\n".join(parts),
                    priority=ContextPriority.MEDIUM,
                    source="data_flow",
                    relevance_score=0.6,
                )

        return None

    def _build_git_context(self, finding: dict) -> ContextElement | None:
        """Build context from git history."""
        git_ctx = self.git_context.get_context_for_finding(finding)

        if "not available" in git_ctx.lower():
            return None

        return ContextElement(
            content=git_ctx,
            priority=ContextPriority.LOW,
            source="git",
            relevance_score=0.4,
        )

    def _build_structure_context(self) -> ContextElement | None:
        """Build context about project structure."""
        stats = self.semantic_graph.get_stats()
        
        parts = ["=== Project Structure ==="]
        parts.append(f"Contracts: {stats['contracts']}")
        parts.append(f"Functions: {stats['functions']}")
        parts.append(f"Dependencies: {stats['edges']}")

        if self.config.include_git_context:
            git_stats = self.git_context.get_stats()
            if git_stats.get("available"):
                parts.append(f"Commits: {git_stats.get('total_commits', 'N/A')}")
                parts.append(f"Contributors: {git_stats.get('contributors', 'N/A')}")

        return ContextElement(
            content="\n".join(parts),
            priority=ContextPriority.LOW,
            source="structure",
            relevance_score=0.2,
        )

    def _assemble_context(self, elements: list[ContextElement]) -> str:
        """
        Assemble context elements.
        If max_tokens is 0 (unlimited), includes everything.
        Otherwise uses priority-based inclusion with token optimization.
        """
        # Unlimited mode: include everything
        if self.config.max_tokens == 0:
            return "\n\n".join(e.content for e in elements)

        # Limited mode: respect token budget
        available_tokens = self.config.max_tokens - self.config.buffer_tokens
        used_tokens = 0
        included_parts = []

        for element in elements:
            if used_tokens + element.token_estimate > available_tokens:
                remaining_tokens = available_tokens - used_tokens
                if remaining_tokens > 200:
                    truncated_chars = int(remaining_tokens / self.config.tokens_per_char)
                    truncated = element.content[:truncated_chars] + "\n... (context truncated)"
                    included_parts.append(truncated)
                break

            included_parts.append(element.content)
            used_tokens += element.token_estimate

        return "\n\n".join(included_parts)

    def get_context_for_agent(self, findings: list[dict]) -> str:
        """
        Build a comprehensive context string for the filter agent.
        Optimized for token usage with structured sections.
        """
        if not self._indexed:
            self.index()

        parts = []
        
        # Project overview
        stats = self.semantic_graph.get_stats()
        parts.append("=== Project Overview ===")
        parts.append(f"Contracts: {stats['contracts']}, Functions: {stats['functions']}")
        
        # List all contracts briefly
        parts.append("\n=== Contracts ===")
        for name, contract in sorted(self.semantic_graph.contracts.items()):
            func_count = len(contract.functions)
            parts.append(f"- {name} ({contract.contract_type}): {func_count} functions")

        # Call graph summary
        if self.config.include_call_graph:
            call_stats = self.call_graph.get_stats()
            parts.append(f"\n=== Call Graph ===")
            parts.append(f"Total calls: {call_stats['total_edges']}")
            parts.append(f"External calls: {call_stats['external_calls']}")

        # Git summary
        if self.config.include_git_context:
            git_stats = self.git_context.get_stats()
            if git_stats.get("available"):
                parts.append(f"\n=== Repository ===")
                parts.append(f"Commits: {git_stats.get('total_commits', 'N/A')}")

        return "\n".join(parts)

    def get_stats(self) -> dict:
        """Get statistics about the context manager."""
        return {
            "indexed": self._indexed,
            "index_time_seconds": self._index_time,
            "semantic_graph": self.semantic_graph.get_stats(),
            "call_graph": self.call_graph.get_stats() if self.config.include_call_graph else None,
            "git": self.git_context.get_stats() if self.config.include_git_context else None,
        }
