# Solidity Auditing Agent

Automated security auditing for Solidity smart contracts. Runs Slither static analysis, uses an LLM to verify findings and generate exploit tests, then produces a markdown report.

## How It Works

```
Foundry Project → Slither (static analysis) → Context Builder → LLM Agent (verify + exploit tests) → Report
```

1. **Index** — Parses all Solidity files, builds a dependency graph and call graph
2. **Analyze** — Runs Slither to find potential vulnerabilities
3. **Verify** — LLM agent inspects each finding, writes exploit tests, applies temporary fixes to confirm
4. **Report** — Generates `audit_report.md` with confirmed vulnerabilities

## Quick Start

```bash
# Install dependencies
uv sync

# Set API key (Anthropic or OpenAI)
export ANTHROPIC_API_KEY=sk-...
# or
export OPENAI_API_KEY=sk-...

# Audit a project
uv run python main.py /path/to/your/foundry/repo

# Audit with OpenAI
uv run python main.py /path/to/repo -m gpt-4o

# Use Docker for Slither/Foundry (no local install needed)
uv run python main.py /path/to/repo --docker
```

## Requirements

- Python 3.13+
- Anthropic API key (`ANTHROPIC_API_KEY`) or OpenAI API key (`OPENAI_API_KEY`)
- For local runs: [Slither](https://github.com/crytic/slither), [Foundry](https://getfoundry.sh/)
- Or use `--docker` (default image: `trailofbits/eth-security-toolbox`)

## Options

| Flag | Description |
|------|-------------|
| `-f, --file <path>` | Audit a single Solidity file instead of the whole repo |
| `-o, --report-output <path>` | Report output path (default: `audit_report.md`) |
| `-m, --model <name>` | LLM model — supports `claude-*`, `gpt-*`, `o1-*`, `o3-*` |
| `--filter-model <name>` | Use a different (cheaper) model for filtering |
| `--api-key <key>` | API key (or use env vars) |
| `--docker` | Run Slither and Foundry inside Docker |
| `--no-git-context` | Skip git history analysis |
| `--no-call-graph` | Skip call graph analysis |
| `--no-data-flows` | Skip data flow analysis |
| `-v, --verbose` | Show all tool calls during verification |

## Supported Models

Any model supported by [litellm](https://docs.litellm.ai/docs/providers):

- **Anthropic**: `claude-sonnet-4-20250514`, `claude-3-5-sonnet`, `claude-3-haiku`
- **OpenAI**: `gpt-4o`, `gpt-4o-mini`, `o1-preview`
- **Full prefix**: `anthropic/claude-sonnet-4-20250514`, `openai/gpt-4o`

## What Gets Detected

The agent verifies findings from Slither and classifies them as true or false positives. Common vulnerability types:

| Type | Severity | Description |
|------|----------|-------------|
| `reentrancy-eth` | High | State updated after external call |
| `arbitrary-send-eth` | High | ETH sent to arbitrary address |
| `weak-prng` | High | Predictable randomness using block values |
| `locked-ether` | Medium | ETH permanently stuck (no withdraw) |
| `incorrect-equality` | Medium | Dangerous strict equality checks |
| `timestamp` | Low | Block timestamp manipulation |
| `missing-zero-check` | Low | No zero-address validation |

## Agent Tools

During verification, the LLM agent has access to:

| Tool | Purpose |
|------|---------|
| `ripgrep` | Search code for patterns |
| `shell` | Run commands (read files, delete tests) |
| `read_file` / `write_file` | Inspect and modify source |
| `foundry_test` | Run `forge test` |
| `get_contract_info` | Get contract structure |
| `get_call_chain` | Trace execution flow |
| `get_data_flow` | Track variable access |

## Output

The agent writes `audit_report.md` in the target repo:

```markdown
# Solidity Security Audit Report

## 1. reentrancy-eth
- **Severity:** High
- **Contract:** ReentrancyVault
- **Function:** withdraw

### Description
The withdraw function updates user balance after making an external call...

### Exploit Scenario
An attacker re-enters withdraw before balance is zeroed...

### Recommendations
- Use checks-effects-interactions pattern
- Add reentrancy guard
```
