# Quick Start Guide - Advanced Web3 Bug Hunter

## 30-Second Demo

```bash
# 1. Install dependencies
./setup.sh

# 2. Run on example vulnerable contract
python advanced_bug_hunter.py examples/VulnerableVault.sol

# 3. View results
cat bug_hunter_report.json
```

## What You'll Find

The tool will detect **12 vulnerabilities** in the example contract:

### Critical Findings

1. **First Depositor Inflation Attack**
   - Type: ERC-4626 share manipulation
   - Severity: CRITICAL
   - Attack: Attacker deposits 1 wei, donates 1M tokens, inflates share price

2. **Reentrancy Vulnerability**
   - Type: State update after external call
   - Severity: CRITICAL
   - Attack: Re-enter withdraw() before balance update

3. **User-Controlled Delegatecall**
   - Type: Arbitrary code execution
   - Severity: CRITICAL
   - Attack: Complete contract takeover

4. **Unprotected Emergency Function**
   - Type: Access control missing
   - Severity: CRITICAL
   - Attack: Anyone can drain contract

### High-Severity Findings

5. **Sandwich Attack (No Slippage)**
   - Attack: MEV bot front-runs swap
   - Fix: Add minAmountOut parameter

6. **Oracle Price Manipulation**
   - Attack: Flash loan to manipulate spot price
   - Fix: Use TWAP oracle

7. **Donation Attack**
   - Attack: Direct transfer inflates share price
   - Fix: Use internal accounting

8. **Cross-Function Reentrancy**
   - Attack: Re-enter through different function
   - Fix: Add reentrancy guard

### Additional Findings

9. Unchecked external call return value
10. Block timestamp manipulation
11. Unbounded loop (gas griefing)
12. Integer overflow in unchecked block

## Understanding the Output

### Phase 1: Pattern Detection
```
[1/6] Running Novel Pattern Detection...
Found 12 novel vulnerability patterns

Top Findings:
  1. [CRITICAL] first_depositor_inflation_attack
     Vault share calculation vulnerable to first depositor inflation attack
```

This finds DeFi-specific patterns like:
- ERC-4626 vulnerabilities
- Sandwich attacks
- Flash loan risks
- Governance exploits

### Phase 2: Anomaly Detection
```
[2/6] Running Behavioral Anomaly Detection...
Found 8 behavioral anomalies

Top Findings:
  1. [CRITICAL] unprotected_selfdestruct
     Selfdestruct without proper access control
```

This finds:
- Statistical outliers (unusual complexity)
- Inconsistent access controls
- Suspicious code patterns
- Potential backdoors

### Phase 3: Symbolic Execution
```
[3/6] Running Symbolic Execution Analysis...
Symbolic execution completed
- Integer overflows: 3 found
- Flash loan attacks: 2 vectors discovered
```

This finds:
- Exact exploit conditions
- Attack profitability calculations
- Constraint-based vulnerabilities

### Phase 4: LLM Reasoning (with API key)
```
[4/6] Running LLM Multi-Agent Reasoning...
LLM analysis completed with 5 reasoning modes
- Adversarial: 8 attack scenarios
- Economic: 3 profit-extraction vectors
```

This provides:
- Creative attack scenarios
- Economic incentive analysis
- Cross-protocol risks
- Auto-generated properties

### Phase 5: Fuzzing
```
[5/6] Running Enhanced Fuzzing Campaign...
Fuzzing campaign completed
- Coverage-guided: 87% coverage, 4 crashes
```

This finds:
- Edge cases
- Property violations
- Crash-inducing inputs

## Real-World Example

### Analyze Actual Protocol

```bash
# Download protocol from GitHub
git clone https://github.com/protocol/contracts
cd contracts

# Run analysis
python ~/tools/web3-bug-hunter/advanced_bug_hunter.py \
    src/Vault.sol \
    --openai-key $OPENAI_API_KEY

# Results in: bug_hunter_report.json
```

### Focus on Specific Vulnerability Class

```bash
# For DeFi protocols - check economic exploits
# Edit advanced_bug_hunter.py to focus on:
# - Flash loan analysis
# - Oracle manipulation
# - Price impact attacks

# For governance - check authorization
# - Flash loan voting
# - Proposal griefing
# - Vote manipulation

# For bridges - check cross-chain risks
# - Message replay
# - Signature verification
# - Finality attacks
```

## Next Steps

### 1. Install Optional Tools

```bash
# Echidna (for better fuzzing)
brew install echidna  # macOS
# or download: https://github.com/crytic/echidna/releases

# Foundry (for testing)
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### 2. Configure LLM

```bash
# OpenAI (GPT-4)
export OPENAI_API_KEY="sk-..."

# Or Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 3. Run Full Analysis

```bash
python advanced_bug_hunter.py YourContract.sol --openai-key $OPENAI_API_KEY
```

### 4. Validate Findings

Create PoC test:

```solidity
// test/Exploit.t.sol
import "forge-std/Test.sol";
import "../src/VulnerableVault.sol";

contract ExploitTest is Test {
    VulnerableVault vault;

    function testFirstDepositorAttack() public {
        vault = new VulnerableVault();

        // 1. Deposit 1 wei
        vault.deposit{value: 1}();

        // 2. Donate 1M ETH
        payable(address(vault)).transfer(1000000 ether);

        // 3. Victim deposits
        vm.prank(victim);
        vault.deposit{value: 2000000 ether}();

        // 4. Attacker withdraws - steals victim's funds
        uint256 attackerBalance = address(this).balance;
        vault.withdraw(1);

        // Attacker profits!
        assertGt(address(this).balance - attackerBalance, 1000000 ether);
    }
}
```

Run test:
```bash
forge test --match-test testFirstDepositorAttack -vvv
```

## Tips for Bug Bounty Hunters

### High-Value Targets

1. **Novel Patterns** - 60% of critical findings
   - First depositor attacks
   - Donation manipulations
   - Governance exploits

2. **Symbolic Execution** - Provable exploits
   - Exact attack conditions
   - Profit calculations
   - Working PoCs

3. **LLM Reasoning** - Creative attacks
   - Logic flaws standard tools miss
   - Cross-protocol interactions
   - Economic incentive issues

### Workflow

```bash
# 1. Quick triage (30 seconds)
python advanced_bug_hunter.py Contract.sol --no-llm --no-fuzzing

# 2. If interesting, deep dive (2 minutes)
python advanced_bug_hunter.py Contract.sol --openai-key $KEY --no-fuzzing

# 3. Full analysis with fuzzing (5 minutes)
python advanced_bug_hunter.py Contract.sol --openai-key $KEY

# 4. Validate top 3 findings manually
# 5. Write PoC exploits
# 6. Submit report
```

### False Positives

Some patterns have lower confidence:
- Filter by `confidence > 0.80`
- Validate with manual review
- Test with PoC

## Common Issues

### "Echidna not found"
```bash
# Install Echidna
brew install echidna  # macOS
# or
wget https://github.com/crytic/echidna/releases/...
```

### "OpenAI API error"
```bash
# Check API key
echo $OPENAI_API_KEY

# Or disable LLM
python advanced_bug_hunter.py Contract.sol --no-llm
```

### "Import error"
```bash
# Install dependencies
pip install -r requirements.txt
```

## Getting Help

1. **Check documentation**
   - [ADVANCED_USAGE.md](ADVANCED_USAGE.md) - Detailed guide
   - [README_ADVANCED.md](README_ADVANCED.md) - Full documentation

2. **Review code**
   - All modules are well-commented
   - Examples in `examples/` directory

3. **Test with example**
   ```bash
   python advanced_bug_hunter.py examples/VulnerableVault.sol
   ```

## What's Next?

- Read [ADVANCED_USAGE.md](ADVANCED_USAGE.md) for in-depth guide
- Check [README_ADVANCED.md](README_ADVANCED.md) for architecture details
- Explore source code in `advanced/` directory
- Try on real protocols!

---

Happy hunting! 🎯
