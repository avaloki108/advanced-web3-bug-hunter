#!/bin/bash
# Environment Switcher for Advanced Web3 Bug Hunter
# Usage: source switch-env.sh [main|mythril|ml]
#
# This script helps you switch between different virtual environments
# for tools that have dependency conflicts.

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to check if environment exists
check_venv_exists() {
    local venv_path=$1
    if [ ! -d "$venv_path" ]; then
        return 1
    fi
    return 0
}

# Function to deactivate current environment
deactivate_current() {
    if [ -n "$VIRTUAL_ENV" ]; then
        deactivate 2>/dev/null || true
    fi
}

# Function to show environment info
show_env_info() {
    local env_name=$1
    local env_path=$2

    echo ""
    echo "Active Environment: $env_name"
    echo "Path: $env_path"
    echo ""
    echo "Installed packages:"
    python -c "import sys; print(f'Python: {sys.version.split()[0]}')"

    # Check for key packages
    if python -c "import z3" 2>/dev/null; then
        python -c "import z3; print(f'z3-solver: {z3.get_version_string()}')"
    fi

    if command -v slither &>/dev/null; then
        echo "slither: $(slither --version 2>&1 | head -n1)"
    fi

    if python -c "import mythril" 2>/dev/null; then
        echo "mythril: installed"
    fi

    if python -c "import torch" 2>/dev/null; then
        echo "pytorch: installed"
    fi

    echo ""
}

# Main script
case "$1" in
    main|"")
        ENV_PATH=".venv"
        ENV_NAME="Main"

        if ! check_venv_exists "$ENV_PATH"; then
            print_error "Main environment not found at $ENV_PATH"
            echo ""
            echo "Create it with:"
            echo "  uv venv .venv"
            echo "  source .venv/bin/activate"
            echo "  uv pip install -r requirements-core.txt"
            return 1 2>/dev/null || exit 1
        fi

        deactivate_current
        source "$ENV_PATH/bin/activate"
        print_success "Activated $ENV_NAME environment"
        echo ""
        echo "This environment includes:"
        echo "  - Core analysis modules (z3-solver, openai, anthropic)"
        echo "  - Compatible with Slither and most tools"
        echo "  - Use for normal analysis: ./hunt Contract.sol"

        if [ "$2" = "--info" ]; then
            show_env_info "$ENV_NAME" "$ENV_PATH"
        fi
        ;;

    mythril)
        ENV_PATH=".venv-mythril"
        ENV_NAME="Mythril"

        if ! check_venv_exists "$ENV_PATH"; then
            print_error "Mythril environment not found at $ENV_PATH"
            echo ""
            echo "Create it with:"
            echo "  uv venv .venv-mythril"
            echo "  source .venv-mythril/bin/activate"
            echo "  uv pip install mythril web3"
            return 1 2>/dev/null || exit 1
        fi

        deactivate_current
        source "$ENV_PATH/bin/activate"
        print_success "Activated $ENV_NAME environment"
        echo ""
        echo "This environment includes:"
        echo "  - Mythril (symbolic execution tool)"
        echo "  - Older z3-solver version (required by Mythril)"
        echo "  - Use with: myth analyze Contract.sol"
        print_warning "Note: Our main tool won't work in this environment"

        if [ "$2" = "--info" ]; then
            show_env_info "$ENV_NAME" "$ENV_PATH"
        fi
        ;;

    ml)
        ENV_PATH=".venv-ml"
        ENV_NAME="ML Enhanced"

        if ! check_venv_exists "$ENV_PATH"; then
            print_error "ML environment not found at $ENV_PATH"
            echo ""
            echo "Create it with:"
            echo "  uv venv .venv-ml"
            echo "  source .venv-ml/bin/activate"
            echo "  uv pip install -r requirements-core.txt"
            echo "  uv pip install transformers torch langchain scikit-learn"
            return 1 2>/dev/null || exit 1
        fi

        deactivate_current
        source "$ENV_PATH/bin/activate"
        print_success "Activated $ENV_NAME environment"
        echo ""
        echo "This environment includes:"
        echo "  - Core analysis modules"
        echo "  - Machine learning tools (transformers, pytorch, scikit-learn)"
        echo "  - Heavy dependencies (~2GB+)"
        echo "  - Use for ML-enhanced analysis: ./hunt Contract.sol"

        if [ "$2" = "--info" ]; then
            show_env_info "$ENV_NAME" "$ENV_PATH"
        fi
        ;;

    list)
        echo ""
        echo "Available Environments:"
        echo ""

        if check_venv_exists ".venv"; then
            print_success ".venv (main) - Core tool + Slither compatible"
        else
            print_warning ".venv (main) - Not created yet"
        fi

        if check_venv_exists ".venv-mythril"; then
            print_success ".venv-mythril - Mythril (separate z3 version)"
        else
            print_warning ".venv-mythril - Not created yet"
        fi

        if check_venv_exists ".venv-ml"; then
            print_success ".venv-ml - ML enhanced (heavy)"
        else
            print_warning ".venv-ml - Not created yet"
        fi

        echo ""
        echo "Current environment:"
        if [ -n "$VIRTUAL_ENV" ]; then
            echo "  $VIRTUAL_ENV"
        else
            echo "  None (no virtual environment activated)"
        fi
        echo ""
        ;;

    status)
        echo ""
        if [ -n "$VIRTUAL_ENV" ]; then
            print_success "Virtual environment is active"
            echo "  Path: $VIRTUAL_ENV"
            echo ""
            echo "Python: $(python --version)"
            echo "Packages: $(pip list 2>/dev/null | wc -l) installed"
        else
            print_warning "No virtual environment is active"
            echo ""
            echo "Activate one with:"
            echo "  source switch-env.sh main"
            echo "  source switch-env.sh mythril"
            echo "  source switch-env.sh ml"
        fi
        echo ""
        ;;

    help|--help|-h)
        cat << 'EOF'

Environment Switcher for Advanced Web3 Bug Hunter

USAGE:
    source switch-env.sh [ENVIRONMENT] [OPTIONS]

ENVIRONMENTS:
    main        Main environment (default)
                - Core analysis modules
                - Compatible with Slither and most tools
                - Use for: ./hunt Contract.sol

    mythril     Mythril environment (separate)
                - Mythril symbolic execution tool
                - Older z3-solver version (required by Mythril)
                - Use for: myth analyze Contract.sol

    ml          ML enhanced environment (heavy)
                - Core modules + ML tools
                - Transformers, PyTorch, scikit-learn (~2GB+)
                - Use for: ./hunt Contract.sol (with ML features)

COMMANDS:
    list        Show all available environments
    status      Show current environment status
    help        Show this help message

OPTIONS:
    --info      Show detailed environment information

EXAMPLES:
    # Switch to main environment
    source switch-env.sh main

    # Switch to Mythril environment
    source switch-env.sh mythril

    # List all environments
    source switch-env.sh list

    # Show current status
    source switch-env.sh status

    # Switch and show details
    source switch-env.sh main --info

NOTES:
    - You must use 'source' (not just './switch-env.sh')
    - Mythril requires separate environment due to z3 conflicts
    - ML environment is large (~2GB+), create only if needed

SETUP:
    Create environments with:

    # Main environment
    uv venv .venv
    source .venv/bin/activate
    uv pip install -r requirements-core.txt
    uv pip install slither-analyzer

    # Mythril environment
    uv venv .venv-mythril
    source .venv-mythril/bin/activate
    uv pip install mythril

    # ML environment
    uv venv .venv-ml
    source .venv-ml/bin/activate
    uv pip install -r requirements-core.txt
    uv pip install transformers torch scikit-learn

EOF
        ;;

    *)
        print_error "Unknown environment: $1"
        echo ""
        echo "Available environments:"
        echo "  main     - Main environment (default)"
        echo "  mythril  - Mythril environment"
        echo "  ml       - ML enhanced environment"
        echo ""
        echo "Commands:"
        echo "  list     - Show all environments"
        echo "  status   - Show current status"
        echo "  help     - Show detailed help"
        echo ""
        echo "Usage: source switch-env.sh [main|mythril|ml|list|status|help]"
        return 1 2>/dev/null || exit 1
        ;;
esac
