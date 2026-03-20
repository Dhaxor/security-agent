"""
Git Context: Context lineage through git history.

Harvests git history to detect regression vulnerabilities, understand "why"
behind code changes, and identify recently modified code that may need scrutiny.
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class CommitInfo:
    """Information about a single commit."""
    hash: str
    short_hash: str
    author: str
    date: datetime
    message: str
    files_changed: list[str] = field(default_factory=list)
    insertions: int = 0
    deletions: int = 0
    is_merge: bool = False

    @property
    def summary(self) -> str:
        return self.message.split("\n")[0][:100]

    def format_relative(self) -> str:
        """Format date as relative time."""
        delta = datetime.now() - self.date
        if delta.days == 0:
            return "today"
        elif delta.days == 1:
            return "yesterday"
        elif delta.days < 7:
            return f"{delta.days} days ago"
        elif delta.days < 30:
            return f"{delta.days // 7} weeks ago"
        else:
            return f"{delta.days // 30} months ago"


@dataclass
class FileChange:
    """Tracks changes to a specific file."""
    file_path: str
    commits: list[CommitInfo] = field(default_factory=list)
    total_insertions: int = 0
    total_deletions: int = 0
    last_modified: datetime | None = None
    change_frequency: float = 0.0  # Changes per week

    @property
    def total_changes(self) -> int:
        return self.total_insertions + self.total_deletions

    @property
    def volatility_score(self) -> float:
        """Score indicating how volatile this file is (0-1)."""
        if not self.commits:
            return 0.0
        
        # Factor in change frequency and recency
        recency_factor = 1.0
        if self.last_modified:
            days_since = (datetime.now() - self.last_modified).days
            recency_factor = max(0, 1 - (days_since / 90))  # Decay over 90 days
        
        return min(1.0, (self.change_frequency * 0.3) + (recency_factor * 0.7))


class GitContext:
    """
    Harvests and analyzes git history for security context.
    
    Features:
    - Recent change detection
    - Regression vulnerability identification
    - File volatility analysis
    - Commit message analysis for security keywords
    """

    # Security-related keywords in commit messages
    SECURITY_KEYWORDS = {
        "fix", "bug", "vulnerability", "security", "exploit", "hack",
        "patch", "emergency", "critical", "reentrancy", "overflow",
        "underflow", "access control", "permission", "auth", "bypass",
        "injection", "dos", "denial", "front-running", "sandwich",
    }

    # Keywords indicating potentially risky changes
    RISKY_CHANGE_KEYWORDS = {
        "refactor", "rewrite", "optimize", "simplify", "cleanup",
        "remove", "delete", "deprecate", "upgrade", "migrate",
    }

    def __init__(self, repo_path: Path):
        self.repo_path = Path(repo_path).resolve()
        self._git_available = self._check_git_available()

    def _check_git_available(self) -> bool:
        """Check if git is available and repo is a git repository."""
        try:
            result = self._run_git(["rev-parse", "--git-dir"])
            return result.returncode == 0
        except Exception:
            return False

    def _run_git(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run a git command."""
        cmd = ["git"] + args
        return subprocess.run(
            cmd,
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def get_recent_commits(self, days: int = 30, max_count: int = 100,
                           file_filter: str | None = None) -> list[CommitInfo]:
        """
        Get recent commits within the specified time window.
        Optionally filter by file path pattern.
        """
        if not self._git_available:
            return []

        since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        
        cmd = [
            "log",
            f"--since={since_date}",
            f"--max-count={max_count}",
            "--format=%H%n%h%n%an%n%aI%n%s%n---",
            "--numstat",
        ]
        
        if file_filter:
            cmd.extend(["--", file_filter])

        result = self._run_git(cmd)
        if result.returncode != 0:
            return []

        return self._parse_git_log(result.stdout)

    def _parse_git_log(self, output: str) -> list[CommitInfo]:
        """Parse git log output into CommitInfo objects."""
        commits = []
        sections = output.split("---")

        for section in sections:
            lines = section.strip().split("\n")
            if len(lines) < 5:
                continue

            try:
                commit_hash = lines[0].strip()
                short_hash = lines[1].strip()
                author = lines[2].strip()
                date_str = lines[3].strip()
                message = lines[4].strip()

                # Parse ISO date
                date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                date = date.replace(tzinfo=None)  # Remove timezone for simplicity

                # Parse file stats
                files_changed = []
                insertions = 0
                deletions = 0
                for line in lines[5:]:
                    if "\t" in line:
                        parts = line.split("\t")
                        if len(parts) >= 3:
                            if parts[0] != "-":
                                insertions += int(parts[0])
                            if parts[1] != "-":
                                deletions += int(parts[1])
                            files_changed.append(parts[2])

                is_merge = "Merge" in message

                commits.append(CommitInfo(
                    hash=commit_hash,
                    short_hash=short_hash,
                    author=author,
                    date=date,
                    message=message,
                    files_changed=files_changed,
                    insertions=insertions,
                    deletions=deletions,
                    is_merge=is_merge,
                ))
            except (ValueError, IndexError) as e:
                logger.debug("Failed to parse commit section: %s", e)
                continue

        return commits

    def get_file_history(self, file_path: str, max_count: int = 50) -> list[CommitInfo]:
        """Get commit history for a specific file."""
        if not self._git_available:
            return []

        result = self._run_git([
            "log",
            f"--max-count={max_count}",
            "--format=%H%n%h%n%an%n%aI%n%s%n---",
            "--numstat",
            "--",
            file_path,
        ])

        if result.returncode != 0:
            return []

        return self._parse_git_log(result.stdout)

    def analyze_file_volatility(self, directory: str | None = None,
                                 days: int = 90) -> dict[str, FileChange]:
        """
        Analyze change frequency for files in a directory.
        Returns dict of file_path -> FileChange with volatility metrics.
        """
        if not self._git_available:
            return {}

        since_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        
        cmd = [
            "log",
            f"--since={since_date}",
            "--format=COMMIT%n%H%n%h%n%an%n%aI%n%s",
            "--numstat",
        ]
        
        if directory:
            cmd.extend(["--", directory])

        result = self._run_git(cmd)
        if result.returncode != 0:
            return {}

        file_changes: dict[str, FileChange] = {}
        current_commit = None

        for line in result.stdout.split("\n"):
            if line.startswith("COMMIT"):
                continue
            
            if len(line) == 40 and all(c in "0123456789abcdef" for c in line):
                # This is a commit hash
                current_commit = line
                continue

            if "\t" in line and current_commit:
                parts = line.split("\t")
                if len(parts) >= 3:
                    ins = int(parts[0]) if parts[0] != "-" else 0
                    dels = int(parts[1]) if parts[1] != "-" else 0
                    file_path = parts[2]

                    if file_path not in file_changes:
                        file_changes[file_path] = FileChange(file_path=file_path)

                    fc = file_changes[file_path]
                    fc.total_insertions += ins
                    fc.total_deletions += dels

        # Calculate change frequency
        weeks = days / 7
        for fc in file_changes.values():
            fc.change_frequency = len(fc.commits) / weeks if weeks > 0 else 0

        return file_changes

    def detect_security_relevant_changes(self, days: int = 30) -> list[CommitInfo]:
        """
        Find commits that are likely security-relevant based on message keywords.
        """
        commits = self.get_recent_commits(days=days)
        security_commits = []

        for commit in commits:
            message_lower = commit.message.lower()
            if any(keyword in message_lower for keyword in self.SECURITY_KEYWORDS):
                security_commits.append(commit)

        return security_commits

    def detect_risky_changes(self, days: int = 30) -> list[CommitInfo]:
        """
        Find commits with risky changes (refactors, rewrites, etc.)
        that might introduce vulnerabilities.
        """
        commits = self.get_recent_commits(days=days)
        risky_commits = []

        for commit in commits:
            message_lower = commit.message.lower()
            if any(keyword in message_lower for keyword in self.RISKY_CHANGE_KEYWORDS):
                risky_commits.append(commit)

        return risky_commits

    def get_hotspots(self, min_changes: int = 5, days: int = 90) -> list[FileChange]:
        """
        Find files that have been changed frequently (hotspots).
        These are often sources of bugs.
        """
        file_changes = self.analyze_file_volatility(days=days)
        
        hotspots = [
            fc for fc in file_changes.values()
            if len(fc.commits) >= min_changes
        ]
        
        # Sort by change frequency (most volatile first)
        hotspots.sort(key=lambda x: x.volatility_score, reverse=True)
        return hotspots

    def get_context_for_finding(self, finding: dict, days: int = 90) -> str:
        """
        Build git context for a Slither finding.
        Includes recent changes to the affected file and related commits.
        """
        if not self._git_available:
            return "Git history not available."

        parts = []
        file_path = finding.get("location", {}).get("file", "")

        if file_path:
            # Get file history
            history = self.get_file_history(file_path, max_count=10)
            if history:
                parts.append(f"=== Recent changes to {file_path} ===")
                for commit in history[:5]:
                    parts.append(
                        f"  {commit.short_hash} ({commit.format_relative()}): "
                        f"{commit.summary}"
                    )
                    if commit.insertions or commit.deletions:
                        parts.append(
                            f"    +{commit.insertions}/-{commit.deletions} lines"
                        )

        # Check for security-relevant commits
        security_commits = self.detect_security_relevant_changes(days=30)
        if security_commits:
            parts.append("\n=== Recent security-related commits ===")
            for commit in security_commits[:5]:
                parts.append(
                    f"  {commit.short_hash} ({commit.format_relative()}): "
                    f"{commit.summary}"
                )

        # Check for risky changes
        risky_commits = self.detect_risky_changes(days=30)
        if risky_commits:
            parts.append("\n=== Recent risky changes (refactors, rewrites) ===")
            for commit in risky_commits[:5]:
                parts.append(
                    f"  {commit.short_hash} ({commit.format_relative()}): "
                    f"{commit.summary}"
                )

        # Get hotspots
        hotspots = self.get_hotspots(min_changes=3, days=90)
        if hotspots:
            parts.append("\n=== Frequently changed files (hotspots) ===")
            for hotspot in hotspots[:5]:
                parts.append(
                    f"  {hotspot.file_path}: "
                    f"{len(hotspot.commits)} changes, "
                    f"volatility={hotspot.volatility_score:.2f}"
                )

        return "\n".join(parts) if parts else "No relevant git context found."

    def get_blame_context(self, file_path: str, line_start: int, line_end: int) -> str:
        """
        Get git blame information for specific lines.
        Shows who last modified each line and when.
        """
        if not self._git_available:
            return "Git blame not available."

        result = self._run_git([
            "blame",
            "-L", f"{line_start},{line_end}",
            "--porcelain",
            file_path,
        ])

        if result.returncode != 0:
            return f"Git blame failed: {result.stderr}"

        # Parse porcelain output
        authors = defaultdict(int)
        dates = []
        
        for line in result.stdout.split("\n"):
            if line.startswith("author "):
                author = line[7:]
                authors[author] += 1
            elif line.startswith("author-time "):
                timestamp = int(line[12:])
                dates.append(datetime.fromtimestamp(timestamp))

        if not authors:
            return "No blame information available."

        # Summarize
        total_lines = sum(authors.values())
        parts = [f"Lines {line_start}-{line_end} in {file_path}:"]
        
        for author, count in sorted(authors.items(), key=lambda x: -x[1]):
            percentage = (count / total_lines) * 100
            parts.append(f"  {author}: {count} lines ({percentage:.0f}%)")

        if dates:
            oldest = min(dates)
            newest = max(dates)
            parts.append(f"Last modified: {newest.strftime('%Y-%m-%d')}")

        return "\n".join(parts)

    def get_stats(self) -> dict:
        """Get statistics about the git repository."""
        if not self._git_available:
            return {"available": False}

        stats = {"available": True}

        # Total commits
        result = self._run_git(["rev-list", "--count", "HEAD"])
        if result.returncode == 0:
            stats["total_commits"] = int(result.stdout.strip())

        # Contributors
        result = self._run_git(["shortlog", "-sn", "HEAD"])
        if result.returncode == 0:
            stats["contributors"] = len(result.stdout.strip().split("\n"))

        # Repository age
        result = self._run_git(["log", "--reverse", "--format=%aI", "-1"])
        if result.returncode == 0:
            try:
                first_commit = datetime.fromisoformat(result.stdout.strip().replace("Z", "+00:00"))
                stats["repo_age_days"] = (datetime.now() - first_commit.replace(tzinfo=None)).days
            except ValueError:
                pass

        return stats
