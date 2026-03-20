"""
Call Graph: Deep context threading for cross-contract call tracing and data flow analysis.

Traces execution paths across 50+ services/contracts, identifies breaking changes
in cross-contract calls, and tracks data flow through storage and parameters.
"""

import logging
from dataclasses import dataclass, field
from typing import Iterator
from collections import defaultdict, deque

from context.semantic_graph import SemanticGraph, ContractNode, FunctionNode

logger = logging.getLogger(__name__)


@dataclass
class CallEdge:
    """Represents a function call between two functions."""
    source_contract: str
    source_function: str
    target_contract: str
    target_function: str
    call_type: str  # direct, delegate, static, create
    line_number: int | None = None
    is_external: bool = False
    is_delegate: bool = False
    arguments: list[str] = field(default_factory=list)

    @property
    def source(self) -> str:
        return f"{self.source_contract}.{self.source_function}"

    @property
    def target(self) -> str:
        return f"{self.target_contract}.{self.target_function}"


@dataclass
class DataFlowPath:
    """Represents a data flow path through contracts."""
    path: list[str]  # List of "contract.function" nodes
    source_var: str
    target_var: str
    flow_type: str  # storage, parameter, return, event
    is_tainted: bool = False  # Whether this path involves user input

    @property
    def length(self) -> int:
        return len(self.path)

    def format(self) -> str:
        return " -> ".join(self.path)


class CallGraph:
    """
    Builds and analyzes call graphs for Solidity contracts.
    
    Features:
    - Cross-contract call tracing
    - Data flow analysis
    - Breaking change detection
    - Reentrancy path identification
    """

    def __init__(self, semantic_graph: SemanticGraph):
        self.graph = semantic_graph
        self.call_edges: list[CallEdge] = []
        self._adjacency: dict[str, list[CallEdge]] = defaultdict(list)
        self._reverse_adjacency: dict[str, list[CallEdge]] = defaultdict(list)
        self._data_flows: list[DataFlowPath] = []
        self._built = False

    def build(self):
        """Build the call graph from the semantic graph."""
        logger.info("Building call graph from semantic graph...")
        self.call_edges.clear()
        self._adjacency.clear()
        self._reverse_adjacency.clear()

        # Build call edges from semantic graph
        for contract_name, contract in self.graph.contracts.items():
            for func_name, func in contract.functions.items():
                for call in func.calls:
                    edge = self._resolve_call(contract_name, func_name, call, func)
                    if edge:
                        self.call_edges.append(edge)
                        self._adjacency[edge.source].append(edge)
                        self._reverse_adjacency[edge.target].append(edge)

        # Analyze data flows
        self._analyze_data_flows()

        self._built = True
        logger.info("Call graph built: %d edges, %d data flows", 
                   len(self.call_edges), len(self._data_flows))

    def _resolve_call(self, source_contract: str, source_function: str, 
                      call_expr: str, source_func: FunctionNode) -> CallEdge | None:
        """Resolve a call expression to a concrete call edge."""
        if "." in call_expr:
            # External call: contract.function() or variable.function()
            parts = call_expr.split(".", 1)
            target_obj = parts[0]
            target_func = parts[1]

            # Try to resolve the target contract
            target_contract = self._resolve_contract_reference(
                target_obj, source_contract, source_func
            )

            if target_contract:
                return CallEdge(
                    source_contract=source_contract,
                    source_function=source_function,
                    target_contract=target_contract,
                    target_function=target_func,
                    call_type="direct",
                    is_external=True,
                )
            else:
                # Unknown target (library, interface, etc.)
                return CallEdge(
                    source_contract=source_contract,
                    source_function=source_function,
                    target_contract=target_obj,
                    target_function=target_func,
                    call_type="direct",
                    is_external=True,
                )
        else:
            # Internal call: function()
            # Check if it's a function in the same contract
            if source_contract in self.graph.contracts:
                contract = self.graph.contracts[source_contract]
                if call_expr in contract.functions:
                    return CallEdge(
                        source_contract=source_contract,
                        source_function=source_function,
                        target_contract=source_contract,
                        target_function=call_expr,
                        call_type="direct",
                        is_external=False,
                    )

        return None

    def _resolve_contract_reference(self, var_name: str, current_contract: str,
                                     current_func: FunctionNode) -> str | None:
        """
        Resolve a variable name to a contract name.
        Uses type information from state variables and parameters.
        """
        if current_contract in self.graph.contracts:
            contract = self.graph.contracts[current_contract]

            # Check state variables
            if var_name in contract.state_variables:
                var_type = contract.state_variables[var_name]
                # Extract contract type from mapping or direct type
                if var_type in self.graph.contracts:
                    return var_type
                # Handle mapping(address => Contract)
                for contract_name in self.graph.contracts:
                    if contract_name in var_type:
                        return contract_name

            # Check function parameters
            for param in current_func.parameters:
                if param.endswith(var_name) or var_name in param:
                    # Try to extract type
                    parts = param.split()
                    if len(parts) >= 2:
                        param_type = parts[0]
                        if param_type in self.graph.contracts:
                            return param_type

        return None

    def _analyze_data_flows(self):
        """Analyze data flow paths through storage and parameters."""
        self._data_flows.clear()

        for contract_name, contract in self.graph.contracts.items():
            for func_name, func in contract.functions.items():
                # Track storage writes
                for write_var in func.storage_writes:
                    # Find functions that read this variable
                    readers = self._find_storage_readers(write_var, contract_name)
                    for reader_contract, reader_func in readers:
                        path = DataFlowPath(
                            path=[f"{contract_name}.{func_name}", f"{reader_contract}.{reader_func}"],
                            source_var=write_var,
                            target_var=write_var,
                            flow_type="storage",
                            is_tainted=self._is_tainted_source(func_name),
                        )
                        self._data_flows.append(path)

    def _find_storage_readers(self, var_name: str, contract_name: str) -> list[tuple[str, str]]:
        """Find all functions that read a given storage variable."""
        readers = []
        
        # Check same contract
        if contract_name in self.graph.contracts:
            contract = self.graph.contracts[contract_name]
            for func_name, func in contract.functions.items():
                if var_name in func.storage_reads:
                    readers.append((contract_name, func_name))

        # Check derived contracts
        dependents = self.graph.get_dependents(contract_name, max_depth=2)
        for dep_contract in dependents:
            if dep_contract in self.graph.contracts:
                contract = self.graph.contracts[dep_contract]
                for func_name, func in contract.functions.items():
                    if var_name in func.storage_reads:
                        readers.append((dep_contract, func_name))

        return readers

    def _is_tainted_source(self, func_name: str) -> bool:
        """Check if a function is a potential source of user input."""
        # Functions that accept external input
        tainted_patterns = [
            "deposit", "withdraw", "transfer", "approve", "mint", "burn",
            "set", "update", "change", "add", "remove", "initialize",
        ]
        return any(pattern in func_name.lower() for pattern in tainted_patterns)

    def trace_call_path(self, start: str, end: str, max_depth: int = 10) -> list[list[str]]:
        """
        Find all call paths between two functions.
        Returns list of paths (each path is a list of "contract.function" strings).
        """
        if not self._built:
            self.build()

        paths = []
        self._dfs_paths(start, end, [], set(), paths, max_depth)
        return paths

    def _dfs_paths(self, current: str, target: str, path: list[str],
                   visited: set[str], paths: list[list[str]], depth: int):
        """DFS to find all paths."""
        if depth <= 0:
            return
        
        if current == target:
            paths.append(path + [current])
            return

        if current in visited:
            return

        visited.add(current)
        path.append(current)

        for edge in self._adjacency.get(current, []):
            self._dfs_paths(edge.target, target, path, visited, paths, depth - 1)

        path.pop()
        visited.remove(current)

    def trace_data_flow(self, var_name: str, contract_name: str) -> list[DataFlowPath]:
        """Trace data flow for a specific variable."""
        return [
            flow for flow in self._data_flows
            if flow.source_var == var_name and 
            (flow.path[0].startswith(contract_name + ".") if flow.path else False)
        ]

    def find_reentrancy_paths(self, contract_name: str) -> list[list[str]]:
        """
        Find potential reentrancy paths.
        Looks for patterns: external call -> state change
        """
        paths = []
        
        if contract_name not in self.graph.contracts:
            return paths

        contract = self.graph.contracts[contract_name]
        for func_name, func in contract.functions.items():
            # Check if function makes external calls
            external_calls = [
                edge for edge in self._adjacency.get(f"{contract_name}.{func_name}", [])
                if edge.is_external
            ]

            if external_calls:
                # Check if state is modified after external call
                if func.storage_writes:
                    path = [f"{contract_name}.{func_name}"]
                    for edge in external_calls:
                        path.append(edge.target)
                    paths.append(path)

        return paths

    def find_breaking_changes(self, changed_contract: str, changed_function: str) -> list[dict]:
        """
        Find potential breaking changes when a function changes.
        Returns list of contracts/functions that depend on the changed function.
        """
        breaking = []
        target = f"{changed_contract}.{changed_function}"

        # Find all callers
        for edge in self._reverse_adjacency.get(target, []):
            breaking.append({
                "affected_contract": edge.source_contract,
                "affected_function": edge.source_function,
                "call_type": edge.call_type,
                "is_external": edge.is_external,
            })

        return breaking

    def get_call_chain_summary(self, contract_name: str, function_name: str,
                               max_depth: int = 3) -> str:
        """
        Get a human-readable summary of call chains from a function.
        Useful for LLM context.
        """
        if not self._built:
            self.build()

        start = f"{contract_name}.{function_name}"
        lines = [f"Call chain from {start}:"]

        visited = set()
        queue = deque([(start, 0)])

        while queue:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            indent = "  " * (depth + 1)
            edges = self._adjacency.get(current, [])
            
            if not edges:
                lines.append(f"{indent}(leaf)")
            else:
                for edge in edges[:5]:  # Limit to 5 per node
                    ext_marker = " [external]" if edge.is_external else ""
                    lines.append(f"{indent}-> {edge.target}{ext_marker}")
                    queue.append((edge.target, depth + 1))

        return "\n".join(lines)

    def get_stats(self) -> dict:
        """Get statistics about the call graph."""
        external_calls = sum(1 for e in self.call_edges if e.is_external)
        internal_calls = len(self.call_edges) - external_calls
        return {
            "total_edges": len(self.call_edges),
            "external_calls": external_calls,
            "internal_calls": internal_calls,
            "data_flows": len(self._data_flows),
            "unique_source_functions": len(set(e.source for e in self.call_edges)),
            "unique_target_functions": len(set(e.target for e in self.call_edges)),
        }
