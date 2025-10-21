# Installation Guide

## Quick Install (Recommended)

```bash
cd /home/dok/tools/web3-bug-hunter

# Run automated setup
./setup.sh
```

This will:
1. Install core dependencies (z3-solver, openai, etc.)
2. Optionally install Slither
3. Set up directories
4. Check for Echidna

## Manual Install

### Step 1: Core Dependencies (Required)

```bash
pip install -r requirements-core.txt
```

This installs:
- z3-solver (for symbolic execution)
- openai (for LLM analysis)
- anthropic (for Claude - optional)
- Development tools

### Step 2: Static Analysis Tools (Optional)

⚠️ **Important**: Mythril and latest z3-solver have version conflicts.

**Option A: Install Slither (Recommended)**
```bash
pip install slither-analyzer
```

**Option B: Install Mythril (Alternative)**
```bash
# Note: This will downgrade z3-solver
pip install mythril
```

**Option C: Use Both (Separate Environments)**
```bash
# Environment 1: Our system + Slither
python -m venv venv-slither
source venv-slither/bin/activate
pip install -r requirements-core.txt
pip install slither-analyzer

# Environment 2: Mythril
python -m venv venv-mythril
source venv-mythril/bin/activate
pip install mythril
```

### Step 3: Fuzzing Tools (Optional)

**Echidna (Recommended for fuzzing)**

macOS:
```bash
brew install echidna
```

Linux:
```bash
wget https://github.com/crytic/echidna/releases/download/v2.2.1/echidna-2.2.1-Linux.tar.gz
tar -xzf echidna-2.2.1-Linux.tar.gz
sudo mv echidna /usr/local/bin/
```

**Foundry (For testing)**
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Verify Installation

```bash
# Test core system
python demo.py

# Test with example contract
python advanced_bug_hunter.py examples/VulnerableVault.sol

# Check if Slither is available
which slither

# Check if Echidna is available
which echidna
```

## Troubleshooting

### Issue: z3 module not found

```bash
pip install z3-solver
```

### Issue: Dependency conflicts

```bash
# Use core requirements only
pip install -r requirements-core.txt

# Skip conflicting tools
```

### Issue: Slither not found

```bash
pip install slither-analyzer
```

### Issue: OpenAI import error

```bash
pip install --upgrade openai
```

## Minimal Setup (Just Advanced Modules)

If you only want the advanced modules (no Slither/Mythril):

```bash
pip install z3-solver openai
```

This is enough to run:
- Symbolic execution
- Pattern detection
- Anomaly detection
- LLM reasoning
- Enhanced fuzzing

## What You Don't Need

You can skip these and still use the advanced modules:
- ❌ Mythril (we have our own symbolic execution)
- ❌ Slither (we have pattern detection, but Slither is useful)
- ❌ Echidna (we have fuzzing, but Echidna is better)

## Recommended Setup

**For bug bounty hunting:**
```bash
pip install -r requirements-core.txt
pip install slither-analyzer
# Skip echidna unless you want deep fuzzing
```

**For complete analysis:**
```bash
pip install -r requirements-core.txt
pip install slither-analyzer
brew install echidna  # or download for Linux
```

**Minimal (just our tools):**
```bash
pip install -r requirements-core.txt
# That's it!
```

## Next Steps

After installation:

1. **Test the demo:**
   ```bash
   python demo.py
   ```

2. **Analyze example contract:**
   ```bash
   python advanced_bug_hunter.py examples/VulnerableVault.sol
   ```

3. **Set up API keys (optional):**
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

4. **Read the guides:**
   - [QUICKSTART.md](QUICKSTART.md)
   - [ADVANCED_USAGE.md](ADVANCED_USAGE.md)
