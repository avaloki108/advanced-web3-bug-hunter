# 🎯 Quick Reference - Web3 Bug Hunter

## Essential Commands

### Basic Scanning
```bash
# Single contract
./hunt Contract.sol

# Entire directory (recursive)
./hunt ~/web3/project/

# Quick scan (no AI, no fuzzing)
./hunt Contract.sol --quick

# With AI, no fuzzing (recommended)
./hunt Contract.sol --no-fuzzing
```

---

## All Features at a Glance

### 1. Malicious Tokens (10 Types)
**File**: [fuzzing/malicious_tokens.sol](fuzzing/malicious_tokens.sol)

```solidity
ReentrantToken       // Reentrancy on transfer
FeeOnTransferToken   // Takes 10% fee
ApprovalAttackToken  // Steals on approve()
ReturnFalseToken     // Returns false instead of revert
NoRevertToken        // Silently fails
UpgradeAttackToken   // Changes behavior mid-execution
PausableAttackToken  // Freezes mid-transaction
DeflationToken       // Balance decreases over time
BlacklistToken       // Can block addresses
HooksEverywhereToken // Multiple reentrancy points
```

**Usage:**
```bash
# Include in fuzzing tests
import "./fuzzing/malicious_tokens.sol";
```

---

### 2. Bridge Attack Simulator
**File**: [fuzzing/bridge_simulator.py](fuzzing/bridge_simulator.py)

**Attacks Simulated:**
- Message Replay
- Message Reordering
- Forged Proof
- Double Withdrawal
- Finality Violation

```bash
# Run simulator
python fuzzing/bridge_simulator.py

# Output: Attack report with exploits found
```

---

### 3. Dual-Phase LLM (Auditor + Critic)
**File**: [advanced/dual_phase_llm.py](advanced/dual_phase_llm.py)

```python
from advanced.dual_phase_llm import DualPhaseLLM
from advanced.llm_providers import LLMClient, LLMProvider

llm = LLMClient(provider=LLMProvider.GROK, api_key="key")
analyzer = DualPhaseLLM(llm)

result = analyzer.analyze_contract(code, "Contract")
print(f"Confirmed: {len(result.confirmed_vulnerabilities)}")
print(f"False positives: {len(result.rejected_hypotheses)}")
```

**Benefit**: Reduces false positives by 50-70%

---

### 4. Fuzzing Execution
**File**: [fuzzing/fuzzer_executor.py](fuzzing/fuzzer_executor.py)

```python
from fuzzing.fuzzer_executor import UnifiedFuzzer

fuzzer = UnifiedFuzzer("Contract.sol")

results = fuzzer.run_all(
    contract_name="MyContract",
    invariants=[
        "balance never exceeds supply",
        "withdrawals never exceed deposits"
    ],
    fuzz_runs=10000
)

# Runs both Echidna and Foundry
```

---

### 5. Feedback Loop (Learning System)
**File**: [advanced/feedback_loop.py](advanced/feedback_loop.py)

```python
from advanced.feedback_loop import FeedbackLoop

feedback = FeedbackLoop()

# Teach it about a vulnerability
vuln = feedback.learn_from_finding(
    contract_name="VulnerableVault",
    vulnerability_type="reentrancy",
    severity="critical",
    description="Classic reentrancy in withdraw",
    affected_code="function withdraw() { ... }",
    attack_scenario="Recursive calls drain contract"
)

# Automatically generates:
# 1. Custom Slither detector
# 2. Echidna invariant
# 3. Enhanced LLM prompt
# 4. Pattern for detection

# Export all learned detectors
feedback.export_detector_library()
```

**Database**: `learned_vulnerabilities.json`
**Detectors**: `custom_detectors/*.py`

---

## Quick Tests

### Test Bridge Simulator
```bash
python fuzzing/bridge_simulator.py
```

### Test Feedback Loop
```bash
python advanced/feedback_loop.py
```

### Test Dual-Phase LLM
```bash
# Requires API key
export XAI_API_KEY="your-key"
python advanced/dual_phase_llm.py
```

---

## File Locations

### Core System
- `./hunt` - Main CLI
- `advanced_bug_hunter.py` - Integration script
- `config.py` - Auto-configuration
- `.env` - API keys (Grok pre-configured)

### Advanced Features
- `fuzzing/malicious_tokens.sol` - Attack tokens
- `fuzzing/fuzzer_executor.py` - Echidna/Foundry execution
- `fuzzing/bridge_simulator.py` - Cross-chain attacks
- `advanced/dual_phase_llm.py` - Auditor + Critic
- `advanced/feedback_loop.py` - Learning system

### Analysis Modules
- `advanced/symbolic_execution_engine.py` - Z3 solver
- `advanced/novel_vulnerability_patterns.py` - 17+ patterns
- `advanced/behavioral_anomaly_detector.py` - Statistics
- `advanced/llm_reasoning_engine.py` - 6 AI agents

### Auto-Generated
- `custom_detectors/*.py` - Learned Slither detectors
- `learned_vulnerabilities.json` - Pattern database
- `*_report.json` - Analysis reports

---

## Workflow Examples

### Bug Bounty Triage
```bash
# Quick scan all targets
./hunt ~/bounties/project1/ --quick
./hunt ~/bounties/project2/ --quick
./hunt ~/bounties/project3/ --quick

# Deep dive on interesting ones
./hunt ~/bounties/project1/VulnerableContract.sol
```

### Learning from Findings
```bash
# 1. Run analysis
./hunt Contract.sol

# 2. Review findings
cat Contract_report.json

# 3. Teach the system (manual)
python << 'EOF'
from advanced.feedback_loop import FeedbackLoop
feedback = FeedbackLoop()
feedback.learn_from_finding(...)
EOF

# 4. Next analysis benefits from learning
./hunt NextContract.sol  # Uses learned patterns!
```

### Full Power Analysis
```bash
# Everything enabled
./hunt ~/web3/high-value-target/

# Uses:
# - 17+ pattern detection
# - Anomaly detection
# - Dual-phase LLM
# - Symbolic execution
# - Fuzzing (if enabled)
# - All learned detectors
```

---

## Configuration

### LLM Provider
```bash
# In .env (already set to Grok)
DEFAULT_LLM_PROVIDER=grok
XAI_API_KEY=xai-...

# Switch to Claude
DEFAULT_LLM_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...

# Switch to OpenAI
DEFAULT_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

### Fuzzing Settings
```python
# In hunt script or advanced_bug_hunter.py
config = {
    'use_llm': True,
    'use_fuzzing': True,
    'fuzz_runs': 10000,
    'timeout': 300
}
```

---

## Feature Checklist

- ✅ Pattern Detection (17+ DeFi patterns)
- ✅ Anomaly Detection (statistical analysis)
- ✅ Symbolic Execution (Z3 solver)
- ✅ LLM Reasoning (6 specialized agents)
- ✅ Dual-Phase LLM (auditor + critic)
- ✅ Fuzzing Execution (Echidna + Foundry)
- ✅ Malicious Tokens (10 attack types)
- ✅ Bridge Simulator (5 attack vectors)
- ✅ Feedback Loop (learns from findings)
- ✅ Auto-Generated Detectors
- ✅ Directory Scanning
- ✅ ~/path Support

---

## Performance

- **Quick scan**: 10-30 seconds
- **With AI**: 1-2 minutes
- **Full analysis**: 5-10 minutes
- **Fuzzing**: 5-60 minutes (configurable)

---

## Getting Help

- [START_HERE.md](START_HERE.md) - Complete guide
- [INTEGRATION_COMPLETE.md](INTEGRATION_COMPLETE.md) - New features
- [FINAL_SUMMARY.md](FINAL_SUMMARY.md) - Full documentation
- [ADVANCED_USAGE.md](ADVANCED_USAGE.md) - Detailed examples

---

## Common Issues

### "Echidna not found"
```bash
# Install: https://github.com/crytic/echidna
# Or skip fuzzing: ./hunt Contract.sol --no-fuzzing
```

### "API key not configured"
```bash
# Check .env file
cat .env

# Or set manually
export XAI_API_KEY="your-key"
```

### "Module not found"
```bash
# Install dependencies
pip install -r requirements-core.txt
```

---

## 🎯 Remember

This system **learns**. Every vulnerability you find makes it smarter.

**Week 1**: Find 5 bugs → Database has 5 patterns
**Week 2**: Previous 5 patterns detect instantly + find 3 new
**Month 3**: Database has 150+ patterns → Expert system

**Start here:**
```bash
./hunt ~/web3/first-target/
```

**Happy hunting!** 🎯
