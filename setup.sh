#!/bin/bash

# Advanced Web3 Bug Hunter - Setup Script
# Installs all dependencies using uv for fast, reliable package management

set -e

echo "=================================================="
echo " Advanced Web3 Bug Hunter - Setup"
echo "=================================================="
echo ""

# Check if uv is installed
echo "[1/6] Checking for uv..."
if ! command -v uv &> /dev/null; then
    echo "uv not found. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    echo "✓ uv installed"
    echo ""
    echo "Please restart your shell or run: source $HOME/.cargo/env"
    echo "Then run this setup script again."
    exit 0
else
    uv_version=$(uv --version 2>&1)
    echo "✓ uv found: $uv_version"
fi
echo ""

# Check Python version
echo "[2/6] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.8 or higher required. Current version: $python_version"
    exit 1
fi

echo "✓ Python version OK: $python_version"
echo ""

# Create virtual environment with uv
echo "[3/6] Creating virtual environment with uv..."
if [ -d ".venv" ]; then
    echo "Virtual environment already exists at .venv"
    read -p "Recreate it? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf .venv
        uv venv
        echo "✓ Virtual environment recreated"
    fi
else
    uv venv
    echo "✓ Virtual environment created at .venv"
fi
echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source .venv/bin/activate
echo "✓ Virtual environment activated"
echo ""

# Install Python dependencies with uv
echo "[4/6] Installing Python dependencies with uv..."
echo "Installing core dependencies..."
uv pip install -r requirements-core.txt

echo ""
echo "Core dependencies installed!"
echo ""
echo "Optional tools (install separately):"
echo "  - Slither:  uv pip install slither-analyzer"
echo "  - Mythril:  uv pip install mythril (conflicts with latest z3)"
echo ""
read -p "Install Slither now? (recommended) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing Slither..."
    uv pip install slither-analyzer
    echo "✓ Slither installed"
fi
echo ""

# Check for Echidna
echo "[5/6] Checking for Echidna..."
if command -v echidna &> /dev/null; then
    echidna_version=$(echidna --version 2>&1 | head -n1)
    echo "✓ Echidna found: $echidna_version"
else
    echo "⚠ Echidna not found. Install from: https://github.com/crytic/echidna"
    echo "  macOS: brew install echidna"
    echo "  Linux: Download from releases page"
fi
echo ""

# Create necessary directories
echo "[6/6] Creating directories..."
mkdir -p advanced
mkdir -p examples
mkdir -p results
mkdir -p corpus
mkdir -p crashes
mkdir -p custom_detectors
echo "✓ Directories created"
echo ""

# Set permissions
chmod +x hunt
chmod +x advanced_bug_hunter.py 2>/dev/null || true
echo "✓ Made scripts executable"
echo ""

echo "=================================================="
echo " Setup Complete!"
echo "=================================================="
echo ""
echo "Virtual environment created at: .venv"
echo ""
echo "To activate the virtual environment:"
echo "  source .venv/bin/activate"
echo ""
echo "Next steps:"
echo "1. Set your API key (optional, for AI analysis):"
echo "   export XAI_API_KEY='your-grok-key-here'"
echo "   # Or use Claude:"
echo "   export ANTHROPIC_API_KEY='your-claude-key-here'"
echo "   # Or use OpenAI:"
echo "   export OPENAI_API_KEY='your-openai-key-here'"
echo ""
echo "2. Run example analysis:"
echo "   ./hunt examples/VulnerableVault.sol"
echo ""
echo "3. Quick scan (no AI):"
echo "   ./hunt examples/VulnerableVault.sol --quick"
echo ""
echo "For detailed usage, see: USAGE.md"
echo ""
echo "Note: Remember to activate the venv before running:"
echo "  source .venv/bin/activate"
echo ""
