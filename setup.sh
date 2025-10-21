#!/bin/bash

# Advanced Web3 Bug Hunter - Setup Script
# Installs all dependencies and sets up the environment

set -e

echo "=================================================="
echo " Advanced Web3 Bug Hunter - Setup"
echo "=================================================="
echo ""

# Check Python version
echo "[1/5] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.8 or higher required. Current version: $python_version"
    exit 1
fi

echo "✓ Python version OK: $python_version"
echo ""

# Install Python dependencies
echo "[2/5] Installing Python dependencies..."
echo "Installing core dependencies (no conflicts)..."
pip install -r requirements-core.txt

echo ""
echo "Core dependencies installed!"
echo ""
echo "Optional tools (install separately):"
echo "  - Slither:  pip install slither-analyzer"
echo "  - Mythril:  pip install mythril (conflicts with latest z3)"
echo ""
read -p "Install Slither now? (recommended) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing Slither..."
    pip install slither-analyzer
    echo "✓ Slither installed"
fi
echo ""

# Check for Echidna
echo "[3/5] Checking for Echidna..."
if command -v echidna &> /dev/null; then
    echidna_version=$(echidna --version 2>&1 | head -n1)
    echo "✓ Echidna found: $echidna_version"
else
    echo "⚠ Echidna not found. Install from: https://github.com/crytic/echidna"
    echo "  macOS: brew install echidna"
    echo "  Linux: Download from releases page"
fi
echo ""

# Check for Slither
echo "[4/5] Checking for Slither..."
if command -v slither &> /dev/null; then
    slither_version=$(slither --version 2>&1)
    echo "✓ Slither found: $slither_version"
else
    echo "Installing Slither..."
    pip install slither-analyzer
    echo "✓ Slither installed"
fi
echo ""

# Create necessary directories
echo "[5/5] Creating directories..."
mkdir -p advanced
mkdir -p examples
mkdir -p results
mkdir -p corpus
mkdir -p crashes
echo "✓ Directories created"
echo ""

# Set permissions
chmod +x advanced_bug_hunter.py
echo "✓ Made scripts executable"
echo ""

echo "=================================================="
echo " Setup Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Set your OpenAI API key:"
echo "   export OPENAI_API_KEY='your-key-here'"
echo ""
echo "2. Run example analysis:"
echo "   python advanced_bug_hunter.py examples/VulnerableVault.sol"
echo ""
echo "3. With LLM analysis:"
echo "   python advanced_bug_hunter.py examples/VulnerableVault.sol --openai-key \$OPENAI_API_KEY"
echo ""
echo "For detailed usage, see: ADVANCED_USAGE.md"
echo ""
