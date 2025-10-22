# Quick Start

Get started in 2 minutes.

## Install

```bash
# Install uv (fast Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create and activate virtual environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements-core.txt
```

Or use the automated setup script:

```bash
./setup.sh
source .venv/bin/activate
```

## Run

```bash
# Analyze a contract
./hunt examples/VulnerableVault.sol

# With AI (Grok pre-configured)
./hunt Contract.sol --no-fuzzing

# Quick scan (no AI)
./hunt Contract.sol --quick
```

## Set Up AI (Optional)

Make sure your virtual environment is activated:

```bash
source .venv/bin/activate

# Then set your API key:

# Grok (recommended)
export XAI_API_KEY="your-key"

# Or Claude
export ANTHROPIC_API_KEY="your-key"

# Or OpenAI
export OPENAI_API_KEY="your-key"
```

## View Results

```bash
cat bug_hunter_report.json | python -m json.tool
```

## What You'll Find

On the example `VulnerableVault.sol`:
- **17 vulnerabilities total**
- 1 Critical, 14 High, 2 Medium
- ERC-4626 inflation, reentrancy, oracle manipulation, etc.

## Common Commands

Always activate the virtual environment first:

```bash
source .venv/bin/activate

# Single file
./hunt Contract.sol

# Entire directory
./hunt ~/projects/my-protocol/

# Python script (more options)
python advanced_bug_hunter.py Contract.sol

# Disable modules
./hunt Contract.sol --no-fuzzing
./hunt Contract.sol --quick  # no AI, no fuzzing
```

## Next Steps

- See [INSTALL.md](INSTALL.md) for detailed setup
- See [USAGE.md](USAGE.md) for complete guide
- Try: `./hunt examples/VulnerableVault.sol`
