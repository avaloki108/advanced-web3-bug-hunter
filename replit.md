# Advanced Web3 Bug Hunter

## Overview
AI-powered smart contract security analyzer that finds vulnerabilities other tools miss. This tool combines symbolic execution, novel pattern detection, behavioral analysis, and optional LLM reasoning to identify security flaws in Solidity smart contracts.

## Project Type
**Command-Line Tool (CLI)** - Smart contract security analysis tool for Web3/DeFi protocols

## Current State
The project is fully configured and ready to use in Replit. All dependencies are installed and the demo workflow is set up to analyze an example vulnerable smart contract.

## Recent Changes
- **2025-10-23**: Initial Replit setup
  - Installed Python 3.11 and all required dependencies
  - Updated .gitignore to exclude Replit-specific files
  - Configured demo workflow to run security analysis on example contract
  - Successfully tested with VulnerableVault.sol example

## Quick Start

### Running the Tool
The workflow automatically runs a quick analysis on an example vulnerable smart contract. You can modify the workflow or run the tool manually:

```bash
# Quick scan (no AI) - fastest
python hunt examples/VulnerableVault.sol --quick

# With AI analysis (requires API key)
python hunt examples/VulnerableVault.sol

# Analyze entire directory
python hunt examples/

# Full analysis with all features
python hunt MyContract.sol
```

### Command Options
- `--quick` - Skip LLM and fuzzing (fastest)
- `--no-llm` - Skip LLM analysis only
- `--no-fuzzing` - Skip fuzzing only
- `--help` - Show usage help

## Project Architecture

### Core Components
1. **Pattern Detection** (`advanced/novel_vulnerability_patterns.py`)
   - Detects DeFi-specific vulnerabilities
   - ERC-4626 inflation attacks, oracle manipulation, etc.

2. **Symbolic Execution** (`advanced/symbolic_execution_engine.py`)
   - Z3 solver-based mathematical proof of exploitability
   - Path exploration and constraint solving

3. **Behavioral Analysis** (`advanced/behavioral_anomaly_detector.py`)
   - Detects unusual contract behaviors
   - Identifies hidden backdoors and edge cases

4. **LLM Reasoning** (Optional - `advanced/llm_reasoning_engine.py`)
   - Multi-agent AI analysis
   - Requires API key (Grok, OpenAI, or Claude)

5. **Learning System** (`advanced/adaptive_learning.py`)
   - Gets smarter with each scan
   - Learns from validated findings

### Key Files
- `hunt` - Main CLI entry point
- `config.py` - Configuration management
- `advanced_bug_hunter.py` - Core analysis orchestrator
- `examples/` - Example vulnerable contracts for testing
- `detectors/` - 15+ specialized vulnerability detectors

## Configuration

### API Keys (Optional)
The tool works without API keys but is more powerful with LLM analysis. To enable:

1. Copy `.env.example` to `.env`
2. Add your API key:
   ```bash
   XAI_API_KEY=your-grok-key-here
   # OR
   OPENAI_API_KEY=your-openai-key-here
   # OR
   ANTHROPIC_API_KEY=your-anthropic-key-here
   ```
3. Run analysis without `--quick` flag

Get API keys from:
- Grok: https://console.x.ai/
- OpenAI: https://platform.openai.com/
- Claude: https://console.anthropic.com/

### Environment Variables
- `XAI_API_KEY` - Grok API key (recommended)
- `OPENAI_API_KEY` - OpenAI GPT-4 key
- `ANTHROPIC_API_KEY` - Claude API key
- `DEFAULT_LLM_PROVIDER` - Provider choice (grok/openai/claude)
- `USE_LLM` - Enable/disable LLM (true/false)
- `USE_FUZZING` - Enable/disable fuzzing (true/false)

## Output

### Analysis Results
Results are saved to JSON files:
- `<ContractName>_report.json` - Detailed findings
- `bug_hunter_report.json` - Comprehensive analysis report

### View Results
```bash
# Pretty print JSON report
cat VulnerableVault_report.json | python -m json.tool

# List all reports
ls -1 *_report.json
```

### Typical Output
- Novel vulnerability patterns detected
- Behavioral anomalies found
- Rare/niche vulnerabilities
- Symbolic execution results
- Proof-of-Concept exploits (when applicable)
- Multi-layer verification results
- Learning system updates

## Features

### What It Finds
- **Cross-contract reentrancy** - $60M+ in historical losses
- **ERC-4626 inflation attacks** - $80M+ Rari, Hundred Finance
- **Oracle manipulation** - $130M Cream Finance
- **Flash loan exploits** - $34M Harvest Finance
- **Privilege escalation** - Via external calls
- **Access control bypass** - Across contracts
- **State inconsistencies** - Between contracts
- **20+ DeFi-specific patterns** - More than standard tools

### Advanced Capabilities
- ✅ AI-powered multi-agent reasoning
- ✅ Z3 symbolic execution for mathematical proof
- ✅ Automated PoC generation
- ✅ Adaptive learning (improves with each scan)
- ✅ Cross-contract analysis
- ✅ Multi-layer verification pipeline
- ✅ False positive reduction (30-50% vs 80-90%)

## Dependencies

### Python Packages (Installed)
- `z3-solver` - Symbolic execution engine
- `openai` - OpenAI API client
- `anthropic` - Claude API client
- `langgraph` - Multi-agent orchestration
- `rich` - Pretty terminal output
- `python-dotenv` - Environment management
- `pytest` - Testing framework

### Optional Tools (Not Required)
- Slither - Static analysis (install separately if needed)
- Echidna - Fuzzing (install separately if needed)
- Foundry - Smart contract testing

## User Preferences
None recorded yet. The tool uses default configuration suitable for most users.

## Notes
- The tool is designed for security researchers and smart contract auditors
- All vulnerabilities found should be validated manually
- Example contracts in `examples/` are intentionally vulnerable for testing
- The learning system improves accuracy over time
- Reports include severity ratings: CRITICAL, HIGH, MEDIUM, LOW
- Always run on test/example contracts first to understand the output

## Documentation
- `README.md` - Project overview and quick start
- `QUICKSTART.md` - 2-minute getting started guide
- `USAGE.md` - Complete usage documentation
- `INSTALL.md` - Detailed installation instructions
- `CROSS_CONTRACT_ANALYSIS.md` - Cross-contract analysis guide
- `detectors/README_ELITE_DETECTORS.md` - Detector documentation

## Support
For issues or questions:
1. Check the documentation files listed above
2. Review example contracts and their analysis results
3. Run with `--help` flag for command options
4. Ensure API keys are set if using LLM features
