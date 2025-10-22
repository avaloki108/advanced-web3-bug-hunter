# Installation

## Quick Install

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment
uv venv

# Activate it
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements-core.txt
```

Or use the automated setup script:

```bash
./setup.sh
source .venv/bin/activate
```

That's it! Test with:

```bash
./hunt examples/VulnerableVault.sol
```

## What Gets Installed

**Core Dependencies (requirements-core.txt):**
- **uv** - Fast Python package manager (replaces pip)
- **Virtual environment** - Isolated Python environment at `.venv/`
- **z3-solver** - Symbolic execution engine
- **openai** - AI analysis (Grok/OpenAI)
- **anthropic** - AI analysis (Claude)
- **pytest** - Testing framework
- **python-dotenv** - Environment variable management
- **rich** - Beautiful terminal output

**Optional Tools (requirements-tools.txt):**
- **slither-analyzer** - Static analysis (recommended)
- **web3** - Blockchain interaction
- **py-solc-x** - Solidity compiler wrapper
- **hypothesis** - Property-based testing
- **scikit-learn** - Machine learning for anomaly detection
- **graphviz** - Visualization
- **And many more** (see requirements-tools.txt)

## Optional Tools Installation

Activate your virtual environment first:

```bash
source .venv/bin/activate

# Then set your API key:

# Grok (recommended)
export XAI_API_KEY="your-key-here"

# Or Claude
export ANTHROPIC_API_KEY="your-key-here"

# Or OpenAI
export OPENAI_API_KEY="your-key-here"
```

Get API keys:
- Grok: https://x.ai/api
- Claude: https://console.anthropic.com
- OpenAI: https://platform.openai.com/api-keys

## Installing Optional Security Tools

### Profile-Based Installation

Choose based on your needs:

**Profile 1: Minimal (Just Slither)**
```bash
source .venv/bin/activate
uv pip install slither-analyzer
```

**Profile 2: Standard (Recommended for Bug Bounties)**
```bash
source .venv/bin/activate
uv pip install slither-analyzer web3 py-solc-x hypothesis requests
```

**Profile 3: Advanced (Full Analysis Suite)**
```bash
source .venv/bin/activate
uv pip install slither-analyzer web3 py-solc-x hypothesis requests \
               graphviz matplotlib pandas scikit-learn numpy crytic-compile
```

**Profile 4: ML Enhanced (With Machine Learning)**
```bash
source .venv/bin/activate
uv pip install slither-analyzer web3 scikit-learn numpy pandas \
               transformers torch langchain
```
*Note: This installs ~2GB of ML libraries*

### Individual Tools

**Slither (Recommended - No Conflicts)**
```bash
source .venv/bin/activate
uv pip install slither-analyzer
```

**Web3.py (Blockchain Interaction)**
```bash
source .venv/bin/activate
uv pip install web3 py-solc-x
```

**Visualization Tools**
```bash
source .venv/bin/activate
uv pip install graphviz matplotlib pandas
```

**Machine Learning Tools**
```bash
source .venv/bin/activate
uv pip install scikit-learn numpy pandas
```

### External Tools (Not Python Packages)

**Echidna (for fuzzing)

**macOS:**
```bash
brew install echidna
```

**Linux:**
```bash
wget https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Linux.tar.gz
tar -xzf echidna-2.2.1-Linux.tar.gz
sudo mv echidna /usr/local/bin/
```

### Foundry (for testing)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Solidity Compiler Management**
```bash
source .venv/bin/activate
uv pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

## Multi-Environment Setup (For Conflicting Tools)

Some tools have dependency conflicts. Use separate virtual environments:

### Setup 1: Main Environment (Our Tool + Slither)

```bash
# Create main environment
uv venv .venv
source .venv/bin/activate

# Install core + Slither
uv pip install -r requirements-core.txt
uv pip install slither-analyzer web3 py-solc-x

# Use this for normal analysis
./hunt Contract.sol
```

### Setup 2: Mythril Environment (Separate)

**Why separate?** Mythril requires z3-solver<4.12, but our tool needs z3-solver>=4.12

```bash
# Create Mythril environment
uv venv .venv-mythril
source .venv-mythril/bin/activate

# Install Mythril
uv pip install mythril web3

# Use Mythril
myth analyze Contract.sol
```

### Setup 3: Heavy ML Environment (Optional)

**Why separate?** Transformers/PyTorch are huge (~2GB+)

```bash
# Create ML environment
uv venv .venv-ml
source .venv-ml/bin/activate

# Install core + ML tools
uv pip install -r requirements-core.txt
uv pip install transformers torch langchain scikit-learn

# Use for ML-enhanced analysis
./hunt Contract.sol
```

### Switching Between Environments

```bash
# Deactivate current environment
deactivate

# Activate main environment
source .venv/bin/activate

# Or activate Mythril environment
source .venv-mythril/bin/activate

# Or activate ML environment
source .venv-ml/bin/activate
```

### Environment Management Script

Create a helper script `switch-env.sh`:

```bash
#!/bin/bash
# Usage: source switch-env.sh [main|mythril|ml]

case "$1" in
    main)
        deactivate 2>/dev/null
        source .venv/bin/activate
        echo "✓ Activated main environment"
        ;;
    mythril)
        deactivate 2>/dev/null
        source .venv-mythril/bin/activate
        echo "✓ Activated Mythril environment"
        ;;
    ml)
        deactivate 2>/dev/null
        source .venv-ml/bin/activate
        echo "✓ Activated ML environment"
        ;;
    *)
        echo "Usage: source switch-env.sh [main|mythril|ml]"
        ;;
esac
```

Then use:
```bash
source switch-env.sh main
source switch-env.sh mythril
source switch-env.sh ml
```

## Verify Installation

```bash
# Activate virtual environment
source .venv/bin/activate

# Test core system
python demo.py

# Test with example
./hunt examples/VulnerableVault.sol

# Check installed packages
uv pip list

# Check tools
which slither
which echidna
which uv
which solc

# Verify z3-solver version (should be >=4.12)
python -c "import z3; print(z3.get_version_string())"

# Verify Slither
slither --version

# Test Mythril (if in mythril venv)
source .venv-mythril/bin/activate
myth version
```

## Complete Installation Examples

### Example 1: Bug Bounty Hunter Setup

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# Create main environment
uv venv .venv
source .venv/bin/activate

# Install core dependencies
uv pip install -r requirements-core.txt

# Install security tools
uv pip install slither-analyzer web3 py-solc-x hypothesis

# Install external tools
brew install echidna  # macOS
# or download from GitHub for Linux

# Set API key
export XAI_API_KEY="your-grok-key"

# Test
./hunt examples/VulnerableVault.sol
```

### Example 2: Full Security Researcher Setup

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# Main environment
uv venv .venv
source .venv/bin/activate
uv pip install -r requirements-core.txt
uv pip install slither-analyzer web3 py-solc-x hypothesis \
               graphviz matplotlib pandas scikit-learn numpy

# Mythril environment (separate)
uv venv .venv-mythril
source .venv-mythril/bin/activate
uv pip install mythril web3

# Back to main
deactivate
source .venv/bin/activate

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Echidna
brew install echidna

# Set API keys
export XAI_API_KEY="your-grok-key"
export ANTHROPIC_API_KEY="your-claude-key"

# Test main environment
./hunt examples/VulnerableVault.sol

# Test Mythril environment
source .venv-mythril/bin/activate
myth analyze examples/VulnerableVault.sol
```

### Example 3: CI/CD Setup

```bash
# In your GitHub Actions or CI pipeline
- name: Setup Main Environment
  run: |
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
    uv venv .venv
    source .venv/bin/activate
    uv pip install -r requirements-core.txt
    uv pip install slither-analyzer

- name: Run Security Scan
  run: |
    source .venv/bin/activate
    ./hunt contracts/ --quick
```

## Troubleshooting

**"uv not found"**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env
```

**"z3 module not found"**
```bash
source .venv/bin/activate
uv pip install z3-solver
```

**"slither not found"**
```bash
source .venv/bin/activate
uv pip install slither-analyzer
```

**"API key error"**
```bash
export XAI_API_KEY="your-key"
# Or run without AI: ./hunt Contract.sol --quick
```

**Virtual environment not activated**
```bash
source .venv/bin/activate
```

**"Conflicting dependencies"**
```bash
# Use separate environments for conflicting tools
uv venv .venv-mythril
source .venv-mythril/bin/activate
uv pip install mythril
```

**"Tool X not found after installation"**
```bash
# Make sure venv is activated
source .venv/bin/activate

# Verify installation
uv pip list | grep tool-name

# Reinstall if needed
uv pip install --force-reinstall tool-name
```

**"z3-solver version conflict"**
```bash
# Our tool requires z3>=4.12
# Mythril requires z3<4.12
# Solution: Use separate venvs (see Multi-Environment Setup above)
```

**"Out of disk space" (ML tools)**
```bash
# Transformers/PyTorch are ~2GB+
# Install in separate venv only if needed
uv venv .venv-ml
source .venv-ml/bin/activate
uv pip install transformers torch
```

## Installation Recommendations

### For Different Use Cases

**Bug Bounty Hunting:**
```bash
source .venv/bin/activate
uv pip install -r requirements-core.txt
uv pip install slither-analyzer web3 hypothesis
```

**Smart Contract Auditing:**
```bash
source .venv/bin/activate
uv pip install -r requirements-core.txt
uv pip install slither-analyzer web3 py-solc-x graphviz
brew install echidna
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

**Security Research:**
```bash
# Main environment
source .venv/bin/activate
uv pip install -r requirements-core.txt
uv pip install slither-analyzer web3 scikit-learn pandas numpy

# Mythril environment
uv venv .venv-mythril
source .venv-mythril/bin/activate
uv pip install mythril
```

**Academic/Learning:**
```bash
source .venv/bin/activate
uv pip install -r requirements-core.txt
uv pip install slither-analyzer
# Minimal setup, expand as needed
```

## Minimal Setup

Just want the core tool?

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create venv and install minimal dependencies
uv venv
source .venv/bin/activate
uv pip install z3-solver openai

# Run without AI
./hunt Contract.sol --quick
```

This skips AI and fuzzing but still runs:
- Pattern detection (20+ DeFi vulnerabilities)
- Symbolic execution (Z3)
- Anomaly detection

## Disk Space Requirements

- **Minimal** (core only): ~100MB
- **Standard** (core + slither): ~150MB
- **Advanced** (core + slither + web3 + viz): ~300MB
- **ML Enhanced** (core + ML tools): ~2.5GB
- **Full Suite** (multiple venvs): ~3GB

## System Requirements

- **Python**: 3.8 or higher (3.10+ recommended)
- **Memory**: 4GB RAM minimum (8GB recommended for ML)
- **Storage**: See disk space requirements above
- **OS**: Linux, macOS, or WSL2 on Windows
- **uv**: Installed automatically by setup script

## Tool Compatibility Matrix

| Tool | Compatible with Core | Requires Separate Venv | Size |
|------|---------------------|------------------------|------|
| Slither | ✅ Yes | ❌ No | ~50MB |
| Mythril | ❌ No (z3 conflict) | ✅ Yes | ~100MB |
| Web3.py | ✅ Yes | ❌ No | ~30MB |
| Hypothesis | ✅ Yes | ❌ No | ~10MB |
| Scikit-learn | ✅ Yes | ❌ No | ~150MB |
| PyTorch | ✅ Yes (heavy) | ⚠️ Recommended | ~1.5GB |
| Transformers | ✅ Yes (heavy) | ⚠️ Recommended | ~1GB |

## Quick Reference

```bash
# Main environment (day-to-day use)
source .venv/bin/activate
./hunt Contract.sol

# Mythril environment (when needed)
source .venv-mythril/bin/activate
myth analyze Contract.sol

# ML environment (heavy analysis)
source .venv-ml/bin/activate
./hunt Contract.sol  # with ML features

# Check which environment is active
echo $VIRTUAL_ENV

# List installed packages
uv pip list

# Update all packages
uv pip install --upgrade -r requirements-core.txt
```

## Next Steps

- See [QUICKSTART.md](QUICKSTART.md) to start analyzing
- See [USAGE.md](USAGE.md) for complete guide
- See [requirements-tools.txt](requirements-tools.txt) for all optional tools