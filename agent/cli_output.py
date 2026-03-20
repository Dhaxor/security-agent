"""
Clean CLI output with progress indicators, colors, and structured display.
"""

import sys
import logging
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field


class Colors:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    
    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


class Icons:
    """Unicode icons for status."""
    CHECK = "✓"
    CROSS = "✗"
    WARN = "⚠"
    INFO = "ℹ"
    ARROW = "→"
    BULLET = "●"
    STAR = "★"
    SHIELD = "🛡"
    SEARCH = "🔍"
    BUG = "🐛"
    LOCK = "🔒"
    CLOCK = "⏱"
    FILE = "📄"
    GEAR = "⚙"
    SPARKLE = "✨"
    SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Spinner:
    """Animated spinner for long-running operations."""

    def __init__(self, message: str = "Processing"):
        self.message = message
        self._running = False
        self._thread = None
        self._index = 0

    def start(self):
        """Start the spinner."""
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self, final_message: str | None = None):
        """Stop the spinner."""
        self._running = False
        if self._thread:
            self._thread.join()
        # Clear the line
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()
        if final_message:
            print(final_message)

    def _animate(self):
        """Animate the spinner."""
        while self._running:
            frame = Icons.SPINNER[self._index % len(Icons.SPINNER)]
            sys.stdout.write(f"\r{Colors.CYAN}{frame}{Colors.RESET} {self.message}")
            sys.stdout.flush()
            self._index += 1
            time.sleep(0.1)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


class CliOutput:
    """Manages clean CLI output."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._indent = 0
        self._start_time = time.time()

    def _indent_str(self) -> str:
        return "  " * self._indent

    @contextmanager
    def indent(self):
        self._indent += 1
        try:
            yield
        finally:
            self._indent -= 1

    def header(self, text: str):
        """Print a major section header."""
        print()
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  {text}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print()

    def stage(self, number: int, total: int, title: str):
        """Print a stage indicator."""
        print(f"{Colors.BOLD}{Colors.BLUE}[{number}/{total}]{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")

    def success(self, text: str):
        """Print a success message."""
        print(f"{self._indent_str()}{Colors.GREEN}{Icons.CHECK}{Colors.RESET} {text}")

    def warning(self, text: str):
        """Print a warning message."""
        print(f"{self._indent_str()}{Colors.YELLOW}{Icons.WARN}{Colors.RESET} {text}")

    def error(self, text: str):
        """Print an error message."""
        print(f"{self._indent_str()}{Colors.RED}{Icons.CROSS}{Colors.RESET} {text}")

    def info(self, text: str):
        """Print an info message."""
        print(f"{self._indent_str()}{Colors.GRAY}{Icons.BULLET}{Colors.RESET} {text}")

    def detail(self, label: str, value: str):
        """Print a label: value pair."""
        print(f"{self._indent_str()}{Colors.DIM}{label}:{Colors.RESET} {value}")

    def finding(self, index: int, check_type: str, severity: str, contract: str, function: str):
        """Print a finding entry."""
        sev_color = self._severity_color(severity)
        sev_label = severity.upper()[:4]
        print(
            f"{self._indent_str()}"
            f"{sev_color}{Colors.BOLD}[{sev_label}]{Colors.RESET} "
            f"{Colors.BOLD}{check_type}{Colors.RESET} "
            f"{Colors.GRAY}in{Colors.RESET} {contract}.{function}"
        )

    def tool_call(self, tool_name: str, summary: str = ""):
        """Print a tool call (only in verbose mode)."""
        if not self.verbose:
            return
        icon = self._tool_icon(tool_name)
        print(f"{self._indent_str()}{Colors.DIM}{icon} {tool_name}{Colors.RESET}", end="")
        if summary:
            print(f" {Colors.GRAY}{summary}{Colors.RESET}", end="")
        print()

    def batch_progress(self, current: int, total: int, batch_size: int):
        """Print batch processing progress."""
        batch_num = (current - 1) // batch_size + 1
        total_batches = (total + batch_size - 1) // batch_size
        print(
            f"{self._indent_str()}"
            f"{Colors.CYAN}{Icons.GEAR}{Colors.RESET} "
            f"Batch {Colors.BOLD}{batch_num}{Colors.RESET}/{total_batches} "
            f"({Colors.BOLD}{current}{Colors.RESET}-{Colors.BOLD}{min(current + batch_size - 1, total)}{Colors.RESET}"
            f" of {total} findings)"
        )

    def table(self, headers: list[str], rows: list[list[str]], align: list[str] | None = None):
        """Print a formatted table."""
        if not rows:
            return

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))

        # Print header
        header_line = "  ".join(
            f"{Colors.BOLD}{h:<{widths[i]}}{Colors.RESET}" 
            for i, h in enumerate(headers)
        )
        print(f"{self._indent_str()}{header_line}")
        
        # Print separator
        sep_line = "  ".join("─" * w for w in widths)
        print(f"{self._indent_str()}{Colors.DIM}{sep_line}{Colors.RESET}")

        # Print rows
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                if i < len(widths):
                    a = align[i] if align and i < len(align) else "<"
                    cells.append(f"{cell:{a}{widths[i]}}")
            print(f"{self._indent_str()}{'  '.join(cells)}")

    def summary_box(self, title: str, items: dict[str, str]):
        """Print a summary box."""
        max_key = max(len(k) for k in items.keys())
        
        print(f"{self._indent_str()}{Colors.BOLD}{Colors.CYAN}┌─ {title} {'─' * (40 - len(title))}┐{Colors.RESET}")
        for key, value in items.items():
            print(
                f"{self._indent_str()}{Colors.CYAN}│{Colors.RESET} "
                f"{Colors.DIM}{key:>{max_key}}:{Colors.RESET} {value}"
            )
        print(f"{self._indent_str()}{Colors.BOLD}{Colors.CYAN}{'─' * 44}{Colors.RESET}")

    def divider(self):
        """Print a thin divider."""
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")

    def spinner(self, message: str) -> Spinner:
        """Create a spinner with the given message."""
        return Spinner(message)

    def elapsed(self) -> str:
        """Get elapsed time string."""
        elapsed = time.time() - self._start_time
        if elapsed < 60:
            return f"{elapsed:.1f}s"
        return f"{elapsed / 60:.1f}m"

    @property
    def RESET(self) -> str:
        return Colors.RESET

    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        severity = severity.lower()
        if severity in ("critical",):
            return Colors.RED + Colors.BOLD
        elif severity in ("high",):
            return Colors.RED
        elif severity in ("medium",):
            return Colors.YELLOW
        elif severity in ("low",):
            return Colors.BLUE
        return Colors.GRAY

    def _tool_icon(self, tool_name: str) -> str:
        """Get icon for tool type."""
        icons = {
            "get_finding_detail": Icons.SEARCH,
            "ripgrep": Icons.SEARCH,
            "shell": "❯",
            "read_file": "📖",
            "write_file": "📝",
            "foundry_build": "🔨",
            "foundry_test": "🧪",
            "get_contract_info": "📋",
            "get_call_chain": "🔗",
            "get_data_flow": "📊",
            "get_dependencies": "📦",
            "search_contracts": Icons.SEARCH,
            "submit_true_positives": Icons.CHECK,
        }
        return icons.get(tool_name, Icons.GEAR)


class AuditLogHandler(logging.Handler):
    """Custom logging handler that routes to CLI output."""

    def __init__(self, cli: CliOutput):
        super().__init__()
        self.cli = cli
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            msg = self.format(record)
            
            # Route to appropriate CLI method based on content
            if "Stage" in msg and "/4" in msg:
                # Stage headers are printed directly
                pass
            elif "Agent tool:" in msg:
                # Extract tool info
                parts = msg.split("Agent tool:", 1)
                if len(parts) > 1:
                    tool_info = parts[1].strip()
                    tool_parts = tool_info.split("args:", 1)
                    if len(tool_parts) > 1:
                        tool_name = tool_parts[0].strip()
                        self.cli.tool_call(tool_name)
                    else:
                        tool_parts = tool_info.split("command:", 1)
                        if len(tool_parts) > 1:
                            self.cli.tool_call("shell", tool_parts[1].strip())
            elif record.levelno >= logging.ERROR:
                self.cli.error(msg)
            elif record.levelno >= logging.WARNING:
                # Don't show retry warnings in clean mode
                if "Retrying" not in msg:
                    self.cli.warning(msg)
            elif self.cli.verbose:
                # Only show other logs in verbose mode
                if not any(skip in msg for skip in ["Agent tool:", "Model:", "Retrying"]):
                    self.cli.info(msg)
        except Exception:
            pass


def setup_cli_logging(verbose: bool = False) -> CliOutput:
    """Set up clean CLI logging."""
    cli = CliOutput(verbose=verbose)
    
    # Clear existing handlers
    root = logging.getLogger()
    root.handlers.clear()
    
    # Add our handler
    handler = AuditLogHandler(cli)
    root.addHandler(handler)
    root.setLevel(logging.INFO if verbose else logging.WARNING)
    
    return cli
