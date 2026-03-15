# Solidity Auditing Agent

Runs Slither on a Foundry repo, uses an LLM with tools (ripgrep, shell, Foundry, read/write file) to filter and verify findings, then writes a markdown report.

## Run

```bash
# 1. Install dependencies (uv)
uv sync

# 2. Set your API key
export ANTHROPIC_API_KEY=sk-...

# 3. Audit a Foundry project (path = project root)
uv run python main.py /path/to/your/foundry/repo
```

Report is written to `audit_report.md` in the repo (override with `-o report.md`).

## Options

| Option | Description |
|--------|-------------|
| `-f, --file <path>` | Run Slither only on this Solidity file |
| `-o <path>` | Report output path (default: `audit_report.md`) |
| `--slither-output <path>` | Slither JSON output path (default: `slither_findings.json`) |
| `--docker` | Run Slither and Foundry in Docker |
| `-m, --model <name>` | Anthropic model (default: `claude-sonnet-4-20250514`) |
| `--api-key <key>` | Anthropic API key (or use `ANTHROPIC_API_KEY` env) |

## Requirements

- **Python 3.13+**
- **Anthropic API key**
- For local runs: [Slither](https://github.com/crytic/slither), [solc-select](https://github.com/crytic/solc-select), [Foundry](https://getfoundry.sh/)  
- Or use `--docker` (default image: `trailofbits/eth-security-toolbox`)
