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
from agent.config import make_audit_config, infer_provider
from agent.cli_output import CliOutput, Colors, Icons, setup_cli_logging


def main() -> None:
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description="Audit a Foundry/Solidity project with Slither + LLM verification.",
    )
    parser.add_argument(
        "repo_path",
        type=Path,
        help="Path to the Foundry repository (project root).",
    )
    parser.add_argument(
        "-f", "--file",
        dest="target_file",
        type=Path,
        default=None,
        help="Run Slither only on this Solidity file.",
    )
    parser.add_argument(
        "-o", "--report-output",
        default="audit_report.md",
        help="Output path for the report (default: audit_report.md).",
    )
    parser.add_argument(
        "--slither-output",
        default="slither_findings.json",
        help="Path for Slither JSON findings (default: slither_findings.json).",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run Slither and Foundry inside Docker.",
    )
    parser.add_argument(
        "--docker-image",
        default=None,
        help="Docker image for tools (default: trailofbits/eth-security-toolbox).",
    )
    parser.add_argument(
        "-m", "--model",
        default="claude-sonnet-4-20250514",
        help="LLM model (default: claude-sonnet-4-20250514). Supports Anthropic and OpenAI.",
    )
    parser.add_argument(
        "--filter-model",
        default=None,
        help="Model for the filter agent (default: same as --model).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key (or use ANTHROPIC_API_KEY / OPENAI_API_KEY env).",
    )
    parser.add_argument(
        "--no-git-context",
        action="store_true",
        help="Disable git history analysis.",
    )
    parser.add_argument(
        "--no-call-graph",
        action="store_true",
        help="Disable call graph analysis.",
    )
    parser.add_argument(
        "--no-data-flows",
        action="store_true",
        help="Disable data flow analysis.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output including all tool calls.",
    )
    args = parser.parse_args()

    # Set up clean CLI output
    cli = setup_cli_logging(verbose=args.verbose)

    # Print banner
    print()
    print(f"  {Colors.BOLD}{Colors.CYAN}🛡  Solidity Security Audit Agent{Colors.RESET}")
    print(f"  {Colors.DIM}Powered by Slither + LLM verification{Colors.RESET}")
    print()

    # Validate inputs
    repo_path = args.repo_path.resolve()
    if not repo_path.is_dir():
        cli.error(f"Not a directory: {repo_path}")
        sys.exit(1)

    target_file = None
    if args.target_file is not None:
        target_file = args.target_file
        if not target_file.is_absolute():
            target_file = (repo_path / target_file).resolve()
        if not target_file.exists():
            cli.error(f"File not found: {target_file}")
            sys.exit(1)

    # Resolve API key
    api_key = args.api_key
    if not api_key:
        provider = infer_provider(args.model)
        if provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY")
        else:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        cli.warning("API key not set. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.")

    # Print configuration
    cli.detail("Target", str(repo_path))
    if target_file:
        cli.detail("File", target_file.name)
    cli.detail("Model", args.model)
    if args.filter_model:
        cli.detail("Filter Model", args.filter_model)
    cli.detail("Output", args.report_output)
    print()

    # Build config
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
        include_git_context=not args.no_git_context,
        include_call_graph=not args.no_call_graph,
        include_data_flows=not args.no_data_flows,
    )

    # Run audit
    agent = AuditAgent(config, cli=cli)
    result = agent.run()

    # Print results
    print()
    cli.divider()
    print()

    if result.errors:
        for err in result.errors:
            cli.error(err)
        print()

    # Summary
    tp_count = len(result.true_positive_findings)
    total_count = len(result.findings_raw)
    fp_count = total_count - tp_count

    if tp_count > 0:
        print(f"  {Colors.RED}{Colors.BOLD}{Icons.BUG} {tp_count} Vulnerabilities Found{Colors.RESET}")
        print()
        
        # Print findings table
        headers = ["Severity", "Type", "Contract", "Function"]
        rows = []
        for f in result.true_positive_findings:
            sev = f.get("severity", "unknown").upper()
            sev_color = cli._severity_color(f.get("severity", ""))
            rows.append([
                f"{sev_color}{sev[:4]}{Colors.RESET}",
                f.get("check_type", ""),
                f.get("contract", ""),
                f.get("function", ""),
            ])
        cli.table(headers, rows)
        print()
    else:
        print(f"  {Colors.GREEN}{Colors.BOLD}{Icons.CHECK} No Vulnerabilities Found{Colors.RESET}")
        print()

    # Report location
    if result.report_markdown_path:
        print(f"  {Colors.DIM}Report saved to:{Colors.RESET} {result.report_markdown_path}")
    
    print(f"  {Colors.DIM}Completed in {cli.elapsed()}{Colors.RESET}")
    print()

    sys.exit(1 if result.errors else 0)


if __name__ == "__main__":
    main()
