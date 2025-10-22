# Usage Guide

Complete guide to using Advanced Web3 Bug Hunter.

## Prerequisites

Always activate the virtual environment first:

```bash
source .venv/bin/activate
```

If you haven't set up the environment yet, see [INSTALL.md](INSTALL.md).

## Basic Usage

### Analyze a Single Contract

```bash
./hunt Contract.sol
```

This runs all modules:
- Pattern detection (20+ DeFi vulnerabilities)
- Symbolic execution (Z3 solver)
- Anomaly detection
- AI reasoning (if API key set)
- Fuzzing (if Echidna installed)

### Analyze a Directory

```bash
./hunt ~/projects/my-protocol/
```

Recursively finds all `.sol` files and analyzes each one.

### Quick Scan (No AI)

```bash
./hunt Contract.sol --quick
```

Skips AI and fuzzing for faster results.

## CLI Options

### Using the `hunt` Script

```bash
./hunt <path> [options]

Options:
  --quick          Skip AI and fuzzing (fastest)
  --no-fuzzing     Skip fuzzing only
  -o, --output     Custom output file name
```

### Using Python Directly

```bash
python advanced_bug_hunter.py <path> [options]

Options:
  --xai-key KEY           Grok API key (default: from env)
  --claude-key KEY        Claude API key
  --openai-key KEY        OpenAI API key
  --no-llm                Skip AI analysis
  --no-fuzzing            Skip fuzzing
  -o, --output FILE       Output file (default: bug_hunter_report.json)
```

## Examples

### Bug Bounty Workflow

```bash
# 1. Quick triage on multiple targets
./hunt ~/bounties/protocol1/ --quick
./hunt ~/bounties/protocol2/ --quick
./hunt ~/bounties/protocol3/ --quick

# 2. Deep dive on promising contracts
./hunt ~/bounties/protocol1/Vault.sol --no-fuzzing

# 3. Full analysis on high-value target
./hunt ~/bounties/protocol1/Vault.sol

# 4. Review findings
cat bug_hunter_report.json | jq '.vulnerabilities[] | select(.severity=="critical")'
```

### Audit Workflow

```bash
# 1. Full analysis with AI
./hunt src/Protocol.sol

# 2. Generate report
python -m json.tool bug_hunter_report.json > audit_report.json

# 3. Validate high-severity findings
cat audit_report.json | jq '.vulnerabilities[] | select(.severity | IN("critical", "high"))'
```

### CI/CD Integration

```bash
# In your GitHub Actions or CI pipeline
- name: Security Scan
  run: |
    # Install uv
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Setup environment
    uv venv
    source .venv/bin/activate
    uv pip install -r requirements-core.txt
    
    # Run scan
    ./hunt contracts/ --quick --output security-report.json
    
    # Fail if critical vulnerabilities found
    if jq -e '.summary.critical > 0' security-report.json; then
      echo "Critical vulnerabilities found!"
      exit 1
    fi
```

## Understanding the Output

### Summary Section

```json
{
  "summary": {
    "total_findings": 17,
    "critical": 1,
    "high": 14,
    "medium": 2,
    "low": 0
  }
}
```

### Vulnerability Details

```json
{
  "vulnerabilities": [
    {
      "severity": "critical",
      "confidence": 0.95,
      "category": "economic_exploit",
      "name": "first_depositor_inflation_attack",
      "description": "ERC-4626 vault vulnerable to first depositor inflation attack",
      "affected_functions": ["deposit", "mint"],
      "attack_vector": "Step-by-step exploit scenario",
      "exploit_scenario": "Detailed attack walkthrough",
      "remediation": "Mint dead shares on initialization",
      "references": ["Rari $80M hack", "Hundred Finance $7M"]
    }
  ]
}
```

### Filtering Results

```bash
# Only critical findings
jq '.vulnerabilities[] | select(.severity=="critical")' bug_hunter_report.json

# High confidence findings
jq '.vulnerabilities[] | select(.confidence >= 0.8)' bug_hunter_report.json

# Specific category
jq '.vulnerabilities[] | select(.category=="economic_exploit")' bug_hunter_report.json

# Count by severity
jq '[.vulnerabilities[] | .severity] | group_by(.) | map({severity: .[0], count: length})' bug_hunter_report.json
```

## Advanced Features

### Using Different AI Providers

```bash
# Activate virtual environment first
source .venv/bin/activate

# Grok (recommended, fast and cheap)
export XAI_API_KEY="your-key"
./hunt Contract.sol

# Claude (best quality)
export ANTHROPIC_API_KEY="your-key"
python advanced_bug_hunter.py Contract.sol --claude-key $ANTHROPIC_API_KEY

# OpenAI (GPT-4)
export OPENAI_API_KEY="your-key"
python advanced_bug_hunter.py Contract.sol --openai-key $OPENAI_API_KEY
```

### Custom Analysis Focus

Edit `config.py` to focus on specific vulnerability types:

```python
# Focus on DeFi vulnerabilities
ENABLED_PATTERNS = [
    "first_depositor_inflation",
    "sandwich_attack",
    "oracle_manipulation",
    "flash_loan_attack"
]

# Focus on access control
ENABLED_PATTERNS = [
    "unprotected_functions",
    "missing_access_control",
    "delegatecall_to_user"
]
```

### Validating Findings

Always validate high-severity findings:

**1. Manual Code Review**
```bash
# Read the vulnerable code
vim Contract.sol +123  # Jump to line 123
```

**2. Write a PoC Test**
```solidity
// test/Exploit.t.sol
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableVault.sol";

contract ExploitTest is Test {
    VulnerableVault vault;
    address attacker = address(0x1);
    address victim = address(0x2);

    function setUp() public {
        vault = new VulnerableVault();
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 1000000 ether);
    }

    function testInflationAttack() public {
        // 1. Attacker deposits minimal amount
        vm.startPrank(attacker);
        vault.deposit{value: 1}();
        
        // 2. Attacker donates to inflate share price
        payable(address(vault)).transfer(1000 ether);
        vm.stopPrank();
        
        // 3. Victim deposits (loses funds due to rounding)
        vm.prank(victim);
        vault.deposit{value: 2000 ether}();
        
        // 4. Attacker withdraws all shares
        vm.prank(attacker);
        uint256 shares = vault.balanceOf(attacker);
        vault.withdraw(shares);
        
        // Verify attacker profited
        assertGt(attacker.balance, 100 ether);
    }
}
```

**3. Run the Test**
```bash
forge test --match-test testInflationAttack -vvvv
```

## Working with Large Codebases

### Analyze Specific Contracts

```bash
# Only analyze vault contracts
find contracts/ -name "*Vault*.sol" -exec ./hunt {} \;

# Analyze by directory
./hunt contracts/core/
./hunt contracts/governance/
./hunt contracts/periphery/
```

### Batch Analysis

```bash
#!/bin/bash
# analyze_all.sh

for file in contracts/**/*.sol; do
    echo "Analyzing $file..."
    ./hunt "$file" --quick -o "reports/$(basename $file .sol)_report.json"
done

# Combine results
jq -s 'map(.vulnerabilities) | flatten | {vulnerabilities: .}' reports/*.json > combined_report.json
```

### Prioritizing Findings

Focus on high-value targets first:

1. **Core logic** - Vaults, pools, lending
2. **High TVL** - Contracts holding funds
3. **Upgradeable** - Proxy contracts
4. **Admin functions** - Governance, emergency
5. **External integrations** - Oracles, bridges

## Performance Tips

### Speed Up Analysis

```bash
# Skip fuzzing (saves 5-10 minutes)
./hunt Contract.sol --no-fuzzing

# Skip AI (saves 1-2 minutes)
./hunt Contract.sol --quick

# Parallel analysis
ls contracts/*.sol | xargs -P 4 -I {} ./hunt {} --quick
```

### Reduce False Positives

1. **Filter by confidence**
   ```bash
   jq '.vulnerabilities[] | select(.confidence >= 0.8)' bug_hunter_report.json
   ```

2. **Focus on critical/high**
   ```bash
   jq '.vulnerabilities[] | select(.severity | IN("critical", "high"))' bug_hunter_report.json
   ```

3. **Review AI reasoning**
   - AI provides detailed attack scenarios
   - Look for realistic exploit paths
   - Ignore findings with vague descriptions

## Integration with Other Tools

### With Slither

```bash
# Run both tools
slither Contract.sol --json slither_report.json
./hunt Contract.sol -o hunter_report.json

# Compare results
python scripts/compare_reports.py slither_report.json hunter_report.json
```

### With Foundry

```bash
# Run tests first
forge test

# Then security scan
./hunt src/

# Generate combined report
forge coverage && ./hunt src/ && python scripts/merge_reports.py
```

### With Echidna

```bash
# Our tool generates Echidna properties
./hunt Contract.sol

# Extract and run properties
python scripts/extract_properties.py bug_hunter_report.json > echidna.yaml
echidna Contract.sol --config echidna.yaml
```

## Common Patterns

### ERC-4626 Vaults

```bash
./hunt Vault.sol
# Look for: first_depositor_inflation, donation_attack, fee_on_transfer
```

### DEX/AMM

```bash
./hunt Pool.sol
# Look for: sandwich_attack, oracle_manipulation, flash_loan_attack
```

### Lending Protocols

```bash
./hunt LendingPool.sol
# Look for: flash_loan_attack, oracle_manipulation, liquidation_front_running
```

### Governance

```bash
./hunt Governor.sol
# Look for: flash_loan_voting, proposal_griefing, vote_manipulation
```

### Bridges

```bash
./hunt Bridge.sol
# Look for: message_replay, signature_issues, finality_attacks
```

## Troubleshooting

### "Virtual environment not activated"

```bash
source .venv/bin/activate
```

### "No vulnerabilities found"

This is good! But double-check:
- Contract has actual logic (not just interface)
- File path is correct
- Virtual environment is activated
- Try with AI: `./hunt Contract.sol --no-fuzzing`

### "Too many false positives"

Filter the output:
```bash
jq '.vulnerabilities[] | select(.confidence >= 0.85)' bug_hunter_report.json
```

Or disable low-confidence patterns in `config.py`.

### "Analysis too slow"

Speed it up:
```bash
./hunt Contract.sol --quick  # Skip AI and fuzzing
```

Or use parallel processing for multiple files.

### "API rate limit"

Slow down or switch providers:
```bash
# Add delay between requests
for file in *.sol; do
    ./hunt "$file"
    sleep 5
done
```

## Best Practices

1. **Always activate virtual environment** - `source .venv/bin/activate` before running
2. **Always validate critical findings** - Write PoCs
3. **Use version control** - Track reports over time
4. **Combine with manual review** - Tools aren't perfect
5. **Focus on high-value targets** - Prioritize by TVL
6. **Run before each deployment** - Catch issues early
7. **Keep learning** - Tool gets smarter over time

## Getting Help

- Read the code in `advanced/` - Well commented
- Check `examples/` for sample contracts
- Review test files in `tests/`
- Open an issue on GitHub

## Next Steps

- Try on real protocols
- Write custom detectors (see `advanced/novel_vulnerability_patterns.py`)
- Integrate into your workflow
- Share findings responsibly