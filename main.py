"""
Solidity Auditing Agent CLI.

Usage:
  python main.py <repo_path> [options]
  python main.py <repo_path> --file <path_to_sol> [options]

Runs Slither on the repo (or a single file), filters findings with an LLM,
generates Foundry exploit tests for true positives, verifies with temporary fixes,
then produces a markdown report. Fixes are not made permanent.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from agent.audit_agent import AuditAgent
from agent.config import make_audit_config


def main() -> None:
    load_dotenv()
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )
    parser = argparse.ArgumentParser(
        description="Audit a Foundry/Solidity project: run Slither, filter findings with LLM, generate exploit tests and report.",
    )
    parser.add_argument(
        "repo_path",
        type=Path,
        help="Path to the Foundry repository (project root).",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="target_file",
        type=Path,
        default=None,
        help="If set, run Slither only on this Solidity file (path relative to repo or absolute).",
    )
    parser.add_argument(
        "-o",
        "--report-output",
        default="audit_report.md",
        help="Output path for the markdown report (default: audit_report.md).",
    )
    parser.add_argument(
        "--slither-output",
        default="slither_findings.json",
        help="Path for Slither JSON findings (default: slither_findings.json).",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run Slither and Foundry inside Docker (eth-security-toolbox image).",
    )
    parser.add_argument(
        "--docker-image",
        default=None,
        help="Docker image for tools (default: trailofbits/eth-security-toolbox).",
    )
    parser.add_argument(
        "-m",
        "--model",
        default="claude-sonnet-4-20250514",
        help="Anthropic model for exploit/report stages (default: claude-sonnet-4-20250514).",
    )
    parser.add_argument(
        "--filter-model",
        default=None,
        help="Model for the filter agent only (default: same as --model). Use a cheaper model to save cost.",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Anthropic API key (default: ANTHROPIC_API_KEY env).",
    )
    args = parser.parse_args()

    repo_path = args.repo_path.resolve()
    if not repo_path.is_dir():
        print(f"Error: repo path is not a directory: {repo_path}", file=sys.stderr)
        sys.exit(1)

    target_file = None
    if args.target_file is not None:
        target_file = args.target_file
        if not target_file.is_absolute():
            target_file = (repo_path / target_file).resolve()
        if not target_file.exists():
            print(f"Error: target file not found: {target_file}", file=sys.stderr)
            sys.exit(1)

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Warning: ANTHROPIC_API_KEY not set; LLM calls may fail.", file=sys.stderr)

    config = make_audit_config(
        repo_path=repo_path,
        target_file=target_file,
        slither_output=args.slither_output,
        report_output=args.report_output,
        use_docker=args.docker,
        docker_image=args.docker_image,
        model=args.model,
        api_key=api_key,
        filter_model=args.filter_model,
    )

    logging.info("Audit target: %s", repo_path)
    if target_file:
        logging.info("Single file: %s", target_file.name)
    logging.info("---")

    agent = AuditAgent(config)
    result = agent.run()

    if result.errors:
        for err in result.errors:
            print(f"Error: {err}", file=sys.stderr)

    if result.report_markdown_path:
        print(f"Report written to: {result.report_markdown_path}")
    print(f"True positives: {len(result.true_positive_findings)}")
    print(f"Exploit tests generated: {len(result.exploit_tests)}")

    sys.exit(1 if result.errors else 0)


if __name__ == "__main__":
    main()
