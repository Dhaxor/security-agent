"""
Semantic Graph: AST parsing and dependency graph for Solidity contracts.

Builds a directed graph of contracts, functions, and their relationships.
Supports incremental indexing for large repositories (400k+ files).
"""

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class FunctionNode:
    """Represents a Solidity function."""
    name: str
    contract: str
    file_path: str
    line_start: int
    line_end: int
    visibility: str  # public, private, internal, external
    state_mutability: str  # pure, view, payable, nonpayable
    modifiers: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    return_types: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)  # Functions this function calls
    storage_reads: list[str] = field(default_factory=list)  # State vars read
    storage_writes: list[str] = field(default_factory=list)  # State vars written
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False

    @property
    def qualified_name(self) -> str:
        return f"{self.contract}.{self.name}"

    @property
    def token_estimate(self) -> int:
        """Estimate tokens for this node's context."""
        return 50 + len(self.calls) * 5 + len(self.storage_reads) * 3 + len(self.storage_writes) * 3


@dataclass
class ContractNode:
    """Represents a Solidity contract."""
    name: str
    file_path: str
    line_start: int
    line_end: int
    contract_type: str  # contract, interface, abstract, library
    inherits: list[str] = field(default_factory=list)  # Parent contracts
    functions: dict[str, FunctionNode] = field(default_factory=dict)
    state_variables: dict[str, str] = field(default_factory=dict)  # name -> type
    events: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    modifiers_def: list[str] = field(default_factory=list)
    uses: list[str] = field(default_factory=list)  # Other contracts/libraries used

    @property
    def qualified_name(self) -> str:
        return self.name

    @property
    def token_estimate(self) -> int:
        """Estimate tokens for this node's context."""
        base = 100
        for func in self.functions.values():
            base += func.token_estimate
        return base


@dataclass
class DependencyEdge:
    """Represents a dependency relationship between contracts."""
    source: str  # Contract name
    target: str  # Contract name
    edge_type: str  # inherits, uses, calls, creates
    weight: int = 1  # Strength of relationship
    metadata: dict = field(default_factory=dict)


class SemanticGraph:
    """
    Builds and maintains a semantic graph of Solidity contracts.
    
    Supports:
    - AST-like parsing without external dependencies
    - Incremental indexing for large repos
    - Dependency tracking across contracts
    - Storage access analysis
    """

    def __init__(self):
        self.contracts: dict[str, ContractNode] = {}
        self.edges: list[DependencyEdge] = []
        self._file_cache: dict[str, str] = {}
        self._index: dict[str, set[str]] = defaultdict(set)  # term -> contract names

    def index_file(self, file_path: Path) -> list[ContractNode]:
        """
        Parse a Solidity file and add its contracts to the graph.
        Returns list of contracts found in this file.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning("Failed to read %s: %s", file_path, e)
            return []

        rel_path = str(file_path)
        self._file_cache[rel_path] = content
        contracts = self._parse_contracts(content, rel_path)

        for contract in contracts:
            self.contracts[contract.name] = contract
            # Index contract name and function names for search
            self._index[contract.name.lower()].add(contract.name)
            for func_name in contract.functions:
                self._index[func_name.lower()].add(contract.name)

        # Build edges from this file's contracts
        self._build_edges_for_contracts(contracts)

        return contracts

    def index_directory(self, directory: Path, max_workers: int = 8) -> int:
        """
        Index all Solidity files in a directory tree.
        Uses parallel processing for performance (50k+ files/min target).
        Returns count of contracts indexed.
        """
        import concurrent.futures

        sol_files = list(directory.rglob("*.sol"))
        logger.info("Indexing %d Solidity files from %s", len(sol_files), directory)

        # Filter out common non-source directories
        skip_dirs = {"node_modules", ".git", "lib", "cache", "out", "artifacts"}
        sol_files = [
            f for f in sol_files
            if not any(skip in f.parts for skip in skip_dirs)
        ]

        count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._parse_single_file, f): f for f in sol_files}
            for future in concurrent.futures.as_completed(futures):
                contracts = future.result()
                count += len(contracts)

        # Rebuild all edges after full indexing
        self._rebuild_all_edges()

        logger.info("Indexed %d contracts from %d files", count, len(sol_files))
        return count

    def _parse_single_file(self, file_path: Path) -> list[ContractNode]:
        """Parse a single file without building edges (for parallel indexing)."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return []

        rel_path = str(file_path)
        self._file_cache[rel_path] = content
        contracts = self._parse_contracts(content, rel_path)

        for contract in contracts:
            self.contracts[contract.name] = contract
            self._index[contract.name.lower()].add(contract.name)
            for func_name in contract.functions:
                self._index[func_name.lower()].add(contract.name)

        return contracts

    def _parse_contracts(self, content: str, file_path: str) -> list[ContractNode]:
        """
        Parse contracts from Solidity source.
        Uses regex-based parsing (no AST library dependency).
        """
        contracts = []
        lines = content.split("\n")

        # Find contract/interface/library/abstract declarations
        contract_pattern = re.compile(
            r"^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)"
            r"(?:\s+is\s+([^{]+))?\s*\{"
        )

        i = 0
        while i < len(lines):
            line = lines[i]
            match = contract_pattern.match(line)
            if match:
                is_abstract = bool(match.group(1))
                contract_type = match.group(2)
                contract_name = match.group(3)
                inherits_str = match.group(4) or ""

                if is_abstract:
                    contract_type = "abstract"

                # Parse inheritance
                inherits = [
                    inh.strip().split("(")[0]  # Remove constructor args
                    for inh in inherits_str.split(",")
                    if inh.strip()
                ]

                # Find contract body (matching braces)
                brace_count = 0
                start_line = i
                body_lines = []
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    body_lines.append(lines[j])
                    if brace_count == 0:
                        i = j + 1
                        break
                else:
                    i += 1
                    continue

                body = "\n".join(body_lines)

                # Parse contract body
                functions = self._parse_functions(body, contract_name, start_line)
                state_vars = self._parse_state_variables(body)
                events = self._parse_events(body)
                errors = self._parse_errors(body)
                modifiers = self._parse_modifiers(body)
                uses = self._parse_uses(body)

                contract = ContractNode(
                    name=contract_name,
                    file_path=file_path,
                    line_start=start_line + 1,
                    line_end=i,
                    contract_type=contract_type,
                    inherits=inherits,
                    functions=functions,
                    state_variables=state_vars,
                    events=events,
                    errors=errors,
                    modifiers_def=modifiers,
                    uses=uses,
                )
                contracts.append(contract)
            else:
                i += 1

        return contracts

    def _parse_functions(self, body: str, contract_name: str, line_offset: int) -> dict[str, FunctionNode]:
        """Parse functions from contract body."""
        functions = {}

        # Match function declarations
        func_pattern = re.compile(
            r"^\s*function\s+(\w+|fallback|receive)\s*\(([^)]*)\)"
            r"(?:\s+(external|public|internal|private))?"
            r"(?:\s+(pure|view|payable))?"
            r"(?:\s+([^{]*?))?"  # modifiers
            r"(?:\s*returns\s*\(([^)]*)\))?"
            r"\s*\{",
            re.MULTILINE
        )

        lines = body.split("\n")
        for i, line in enumerate(lines):
            match = func_pattern.search(line)
            if match:
                func_name = match.group(1)
                params_str = match.group(2) or ""
                visibility = match.group(3) or "public"
                mutability = match.group(4) or "nonpayable"
                modifiers_str = match.group(5) or ""
                returns_str = match.group(6) or ""

                # Parse parameters
                params = [p.strip() for p in params_str.split(",") if p.strip()]
                
                # Parse modifiers
                modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]
                
                # Parse return types
                return_types = [r.strip() for r in returns_str.split(",") if r.strip()]

                # Find function body end
                brace_count = 0
                func_start = i
                func_body_lines = []
                for j in range(i, len(lines)):
                    brace_count += lines[j].count("{") - lines[j].count("}")
                    func_body_lines.append(lines[j])
                    if brace_count == 0:
                        break

                func_body = "\n".join(func_body_lines)
                
                # Analyze function body
                calls = self._extract_function_calls(func_body)
                storage_reads, storage_writes = self._analyze_storage_access(func_body)

                is_constructor = func_name == "constructor"
                is_fallback = func_name == "fallback"
                is_receive = func_name == "receive"

                func_node = FunctionNode(
                    name=func_name,
                    contract=contract_name,
                    file_path="",
                    line_start=line_offset + i + 1,
                    line_end=line_offset + i + len(func_body_lines),
                    visibility=visibility,
                    state_mutability=mutability,
                    modifiers=modifiers,
                    parameters=params,
                    return_types=return_types,
                    calls=calls,
                    storage_reads=storage_reads,
                    storage_writes=storage_writes,
                    is_constructor=is_constructor,
                    is_fallback=is_fallback,
                    is_receive=is_receive,
                )
                functions[func_name] = func_node

        return functions

    def _parse_state_variables(self, body: str) -> dict[str, str]:
        """Parse state variables from contract body."""
        vars_dict = {}
        # Match state variable declarations
        var_pattern = re.compile(
            r"^\s*(mapping\s*\([^)]+\)|\w+(?:\[\])?)\s+(public|private|internal|constant|immutable)?\s*(\w+)\s*[;=]",
            re.MULTILINE
        )
        for match in var_pattern.finditer(body):
            var_type = match.group(1)
            var_name = match.group(3)
            vars_dict[var_name] = var_type
        return vars_dict

    def _parse_events(self, body: str) -> list[str]:
        """Parse event declarations."""
        events = []
        event_pattern = re.compile(r"^\s*event\s+(\w+)\s*\(", re.MULTILINE)
        for match in event_pattern.finditer(body):
            events.append(match.group(1))
        return events

    def _parse_errors(self, body: str) -> list[str]:
        """Parse custom error declarations."""
        errors = []
        error_pattern = re.compile(r"^\s*error\s+(\w+)\s*\(", re.MULTILINE)
        for match in error_pattern.finditer(body):
            errors.append(match.group(1))
        return errors

    def _parse_modifiers(self, body: str) -> list[str]:
        """Parse modifier definitions."""
        modifiers = []
        modifier_pattern = re.compile(r"^\s*modifier\s+(\w+)\s*\(", re.MULTILINE)
        for match in modifier_pattern.finditer(body):
            modifiers.append(match.group(1))
        return modifiers

    def _parse_uses(self, body: str) -> list[str]:
        """Parse contracts/libraries used (via 'using' statements)."""
        uses = []
        using_pattern = re.compile(r"^\s*using\s+(\w+)\s+for", re.MULTILINE)
        for match in using_pattern.finditer(body):
            uses.append(match.group(1))
        return uses

    def _extract_function_calls(self, func_body: str) -> list[str]:
        """Extract function calls from a function body."""
        calls = set()
        # Match method calls: obj.method() or method()
        call_pattern = re.compile(r"(\w+)\s*\.\s*(\w+)\s*\(")
        for match in call_pattern.finditer(func_body):
            obj = match.group(1)
            method = match.group(2)
            # Skip common keywords
            if obj not in {"require", "assert", "revert", "emit", "new", "this"}:
                calls.add(f"{obj}.{method}")

        # Match direct function calls
        direct_pattern = re.compile(r"(?<!\.)\b(\w+)\s*\([^)]*\)")
        for match in direct_pattern.finditer(func_body):
            name = match.group(1)
            if name not in {
                "require", "assert", "revert", "emit", "new", "return",
                "if", "while", "for", "mapping", "address", "bytes", "string",
                "uint", "int", "bool", "keccak256", "abi", "msg", "block", "tx",
            }:
                calls.add(name)

        return list(calls)

    def _analyze_storage_access(self, func_body: str) -> tuple[list[str], list[str]]:
        """Analyze state variable reads and writes."""
        reads = set()
        writes = set()

        # Simple heuristic: assignments to identifiers = writes, other usages = reads
        write_pattern = re.compile(r"(\w+)\s*(?:=|\+=|-=|\*=|/=|%=|<<=|>>=|&=|\|=|\^=)\s*[^=]")
        for match in write_pattern.finditer(func_body):
            var_name = match.group(1)
            if var_name not in {"msg", "block", "tx", "this", "super"}:
                writes.add(var_name)

        # Reads are more complex - for now, track all identifiers used
        read_pattern = re.compile(r"\b([a-z]\w*)\b")
        common_keywords = {
            "require", "assert", "revert", "emit", "return", "if", "else", "while",
            "for", "mapping", "address", "bytes", "string", "uint", "int", "bool",
            "msg", "block", "tx", "this", "super", "true", "false", "new", "delete",
            "storage", "memory", "calldata", "payable", "view", "pure", "external",
            "public", "internal", "private", "virtual", "override",
        }
        for match in read_pattern.finditer(func_body):
            name = match.group(1)
            if name not in common_keywords and name not in writes:
                reads.add(name)

        return list(reads), list(writes)

    def _build_edges_for_contracts(self, contracts: list[ContractNode]):
        """Build dependency edges for a set of contracts."""
        for contract in contracts:
            # Inheritance edges
            for parent in contract.inherits:
                edge = DependencyEdge(
                    source=contract.name,
                    target=parent,
                    edge_type="inherits",
                    weight=3,
                )
                self.edges.append(edge)

            # Usage edges (libraries, etc.)
            for used in contract.uses:
                edge = DependencyEdge(
                    source=contract.name,
                    target=used,
                    edge_type="uses",
                    weight=2,
                )
                self.edges.append(edge)

            # Call edges
            for func in contract.functions.values():
                for call in func.calls:
                    if "." in call:
                        target_contract, target_func = call.split(".", 1)
                        edge = DependencyEdge(
                            source=contract.name,
                            target=target_contract,
                            edge_type="calls",
                            weight=1,
                            metadata={"function": func.name, "calls": target_func},
                        )
                        self.edges.append(edge)

    def _rebuild_all_edges(self):
        """Rebuild all edges after full indexing."""
        self.edges.clear()
        all_contracts = list(self.contracts.values())
        self._build_edges_for_contracts(all_contracts)

    def get_contract_dependencies(self, contract_name: str, max_depth: int = 3) -> set[str]:
        """
        Get all contracts that a given contract depends on (transitively).
        Returns set of contract names within max_depth hops.
        """
        visited = set()
        queue = [(contract_name, 0)]

        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            for edge in self.edges:
                if edge.source == current and edge.target not in visited:
                    queue.append((edge.target, depth + 1))

        visited.discard(contract_name)
        return visited

    def get_dependents(self, contract_name: str, max_depth: int = 3) -> set[str]:
        """
        Get all contracts that depend on a given contract.
        Useful for impact analysis when a contract changes.
        """
        visited = set()
        queue = [(contract_name, 0)]

        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            for edge in self.edges:
                if edge.target == current and edge.source not in visited:
                    queue.append((edge.source, depth + 1))

        visited.discard(contract_name)
        return visited

    def search(self, query: str, max_results: int = 10) -> list[str]:
        """
        Search for contracts/functions matching a query.
        Returns list of contract names.
        """
        query_lower = query.lower()
        results = set()

        # Exact match
        if query_lower in self._index:
            results.update(self._index[query_lower])

        # Partial match
        for term, contracts in self._index.items():
            if query_lower in term or term in query_lower:
                results.update(contracts)

        return list(results)[:max_results]

    def get_context_for_finding(self, finding: dict, max_tokens: int = 15000) -> str:
        """
        Build optimized context for a Slither finding.
        Prioritizes relevant contracts and functions.
        """
        contract_name = finding.get("contract", "")
        function_name = finding.get("function", "")
        parts = []

        # Get the primary contract
        if contract_name and contract_name in self.contracts:
            contract = self.contracts[contract_name]
            parts.append(self._format_contract_context(contract, function_name))

            # Get dependencies
            deps = self.get_contract_dependencies(contract_name, max_depth=2)
            for dep in sorted(deps):
                if dep in self.contracts:
                    dep_contract = self.contracts[dep]
                    parts.append(self._format_contract_context(dep_contract))

        # Estimate tokens and truncate if needed
        total_tokens = 0
        final_parts = []
        for part in parts:
            part_tokens = len(part) // 4  # Rough estimate
            if total_tokens + part_tokens > max_tokens:
                break
            final_parts.append(part)
            total_tokens += part_tokens

        return "\n\n".join(final_parts) if final_parts else "No relevant context found."

    def _format_contract_context(self, contract: ContractNode, focus_function: str = "") -> str:
        """Format a contract's context for LLM consumption."""
        lines = [
            f"=== {contract.name} ({contract.contract_type}) in {contract.file_path} ===",
            f"Lines: {contract.line_start}-{contract.line_end}",
        ]

        if contract.inherits:
            lines.append(f"Inherits: {', '.join(contract.inherits)}")

        if contract.state_variables:
            lines.append("State Variables:")
            for name, var_type in contract.state_variables.items():
                lines.append(f"  - {var_type} {name}")

        if contract.functions:
            lines.append("Functions:")
            for name, func in contract.functions.items():
                focus_marker = " [FOCUS]" if name == focus_function else ""
                lines.append(
                    f"  - {func.visibility} {func.state_mutability} "
                    f"{name}({', '.join(func.parameters)}){focus_marker}"
                )
                if func.calls:
                    lines.append(f"    Calls: {', '.join(func.calls[:5])}")
                if func.storage_writes:
                    lines.append(f"    Writes: {', '.join(func.storage_writes[:5])}")

        if contract.events:
            lines.append(f"Events: {', '.join(contract.events)}")

        if contract.errors:
            lines.append(f"Errors: {', '.join(contract.errors)}")

        return "\n".join(lines)

    def get_stats(self) -> dict:
        """Get statistics about the graph."""
        total_functions = sum(len(c.functions) for c in self.contracts.values())
        return {
            "contracts": len(self.contracts),
            "functions": total_functions,
            "edges": len(self.edges),
            "files_indexed": len(self._file_cache),
        }
