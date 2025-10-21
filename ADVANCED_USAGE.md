# Advanced Web3 Bug Hunter - Usage Guide

## Overview

This advanced bug hunting system combines cutting-edge techniques to find novel vulnerabilities that standard tools miss:

1. **Symbolic Execution with Z3** - Deep path exploration and constraint solving
2. **Novel Pattern Detection** - DeFi-specific vulnerability patterns
3. **Behavioral Anomaly Detection** - Statistical analysis for unusual patterns
4. **Multi-Agent LLM Reasoning** - AI-powered logic flaw discovery
5. **Enhanced Fuzzing** - Coverage-guided and adversarial fuzzing

## Quick Start

### Basic Usage

```bash
# Run comprehensive analysis on a contract
python advanced_bug_hunter.py VulnerableContract.sol
```

### With LLM Analysis

```bash
# Use GPT-4 for advanced reasoning
python advanced_bug_hunter.py VulnerableContract.sol --openai-key YOUR_API_KEY
```

### Disable Components

```bash
# Skip LLM analysis (faster, but misses logic flaws)
python advanced_bug_hunter.py VulnerableContract.sol --no-llm

# Skip fuzzing (for quick static analysis only)
python advanced_bug_hunter.py VulnerableContract.sol --no-fuzzing
```

## Advanced Techniques Explained

### 1. Symbolic Execution Engine

Located in: `advanced/symbolic_execution_engine.py`

**What it does:**
- Uses Z3 SMT solver to explore all possible execution paths
- Finds exact conditions that trigger vulnerabilities
- Generates proof-of-concept exploits automatically

**Novel capabilities:**
- **Integer overflow analysis** - Finds precise values that cause overflow
- **Reentrancy detection** - Symbolic state tracking across external calls
- **Flash loan attack modeling** - Multi-step attack sequence analysis
- **Oracle manipulation** - Price manipulation profit calculation
- **Access control bypass** - Finds conditions to bypass checks

**Example findings:**
```
Vulnerability: Integer Overflow
Operation: add
Left variable: userInput (tainted)
Right variable: balance
Example exploit values:
  userInput = 115792089237316195423570985008687907853269984665640564039457584007913129639935
  balance = 1
```

### 2. Novel Pattern Detector

Located in: `advanced/novel_vulnerability_patterns.py`

**Detects 17+ DeFi-specific vulnerability patterns:**

1. **Sandwich Attack Vulnerability** - Missing slippage protection
2. **Just-in-Time Liquidity Attack** - No minimum lock period
3. **Governance Takeover** - Flash loan voting attacks
4. **Oracle Price Lag Exploit** - Stale price usage
5. **Donation Attack** - Direct balance manipulation
6. **First Depositor Inflation** - ERC-4626 share inflation
7. **Cross-Function Reentrancy** - State inconsistency across functions
8. **Read-Only Reentrancy** - View function exploitation
9. **Spot Price Oracle Manipulation** - DEX reserve manipulation
10. **Slippage Frontrunning** - MEV extraction
11. **Liquidity Pool Draining** - Unrestricted removal
12. **TWAP Manipulation** - Short time windows
13. **Flash Loan Price Oracle Attack** - Single-transaction manipulation
14. **Governance Proposal Griefing** - Spam attacks
15. **Reward Calculation Exploit** - Rounding errors
16. **Vault Inflation Attack** - Share price manipulation
17. **ERC-4626 Share Manipulation** - Donation-based attacks

**Example output:**
```
[MEV_EXTRACTION] sandwich_attack_no_slippage_protection
Description: Function 'swap' lacks slippage protection, vulnerable to sandwich attacks
Severity: HIGH
Confidence: 0.85
Attack Vector: MEV bot front-runs user transaction, manipulates price, then back-runs
Remediation: Add minAmountOut parameter and require(amountOut >= minAmountOut)
```

### 3. Behavioral Anomaly Detector

Located in: `advanced/behavioral_anomaly_detector.py`

**What it detects:**
- **Statistical outliers** - Functions with unusual complexity
- **Inconsistent patterns** - Similar functions with different access controls
- **Anti-patterns** - Violations of best practices
- **Suspicious code** - Potential backdoors or hidden functions

**Metrics analyzed:**
- Cyclomatic complexity
- External call patterns
- State update ordering
- Assembly usage
- Access control consistency
- Gas griefing patterns
- Timestamp dependencies

**Example findings:**
```
[ANTI_PATTERN] state_update_after_external_call
Function: 'withdraw' updates state after external call
Severity: HIGH
Potential Exploit: Classic reentrancy vulnerability
Remediation: Move state updates before external calls
```

### 4. Multi-Agent LLM Reasoning

Located in: `advanced/llm_reasoning_engine.py`

**Five specialized AI agents:**

1. **Adversarial Agent** - Thinks like an attacker
   - Maps attack surfaces
   - Traces privilege boundaries
   - Considers multi-tx sequences
   - Game theory analysis

2. **Economic Agent** - Analyzes incentives
   - Value flow mapping
   - Profit calculations
   - Risk-free attack detection
   - Economic parameter analysis

3. **Composability Agent** - Cross-protocol risks
   - External dependencies
   - Shared state risks
   - Multi-protocol attacks
   - Integration failures

4. **Formal Verification Agent** - Mathematical properties
   - Invariant generation
   - Pre/post-conditions
   - Conservation laws
   - Safety properties

5. **Pattern Matching Agent** - Historical vulnerabilities
   - Compares to known exploits
   - Pattern matching
   - Best practice checking

**Example prompts:**
```
ADVERSARIAL REASONING:
"Think like an attacker. Consider:
- Flash loan attacks
- Oracle manipulation
- Cross-function reentrancy
- ERC-4626 share inflation
[... detailed attack framework ...]"

ECONOMIC REASONING:
"Analyze economic incentives:
- Can attacker profit risk-free?
- Are there misaligned incentives?
- Economic parameter manipulation?
[... game theory framework ...]"
```

### 5. Enhanced Fuzzing Orchestrator

Located in: `advanced/enhanced_fuzzing_orchestrator.py`

**Four fuzzing strategies:**

1. **Coverage-Guided Fuzzing**
   - Tracks code coverage
   - Prioritizes inputs increasing coverage
   - Smart corpus management

2. **Mutation-Based Fuzzing**
   - Intelligent input mutations
   - Vulnerability-targeted mutations
   - Overflow/underflow triggers

3. **Symbolic-Guided Fuzzing**
   - Uses Z3 constraints
   - Generates targeted inputs
   - Path-specific fuzzing

4. **Adversarial Fuzzing**
   - Property-specific attacks
   - Designed to break invariants
   - Exploit-focused inputs

**Mutation strategies:**
```python
- Bit flipping (random bit flip)
- Arithmetic mutations (+/- delta)
- Interesting values (0, 1, MAX_UINT)
- Overflow triggers (2^256 - 2)
- Underflow triggers (1)
- Precision loss triggers (3)
```

## Integration with Existing Tools

### Using with Slither

```bash
# Run Slither first
slither VulnerableContract.sol --json slither_output.json

# Then run advanced analysis
python advanced_bug_hunter.py VulnerableContract.sol
```

### Using with Echidna

```bash
# Generate properties with LLM
python advanced_bug_hunter.py Contract.sol --openai-key KEY

# Extract generated properties
# Add them to your Echidna test contract
# Run Echidna
echidna Contract.sol --config echidna.yaml
```

### Using with Foundry

```bash
# Generate invariant tests
python advanced_bug_hunter.py Contract.sol

# Copy generated tests to Foundry
# Run: forge test --match-contract Invariant
```

## Output Format

The tool generates `bug_hunter_report.json` with:

```json
{
  "contract": "VulnerableContract.sol",
  "timestamp": "2025-10-20T12:00:00",
  "analysis_results": {
    "novel_patterns": {
      "total_patterns": 12,
      "critical": 3,
      "high": 5,
      "patterns": [...]
    },
    "anomalies": {
      "total_anomalies": 8,
      "critical": 2,
      "high": 4,
      "anomalies": [...]
    },
    "symbolic_execution": {
      "overflow_analysis": [...],
      "flash_loan_analysis": [...],
      "oracle_manipulation": [...]
    },
    "llm_reasoning": [...],
    "fuzzing": {...}
  }
}
```

## Best Practices

### 1. Iterative Analysis

Start with quick analysis, then deep dive:

```bash
# Step 1: Quick static analysis (no LLM, no fuzzing)
python advanced_bug_hunter.py Contract.sol --no-llm --no-fuzzing

# Step 2: Add LLM for logic flaws
python advanced_bug_hunter.py Contract.sol --openai-key KEY --no-fuzzing

# Step 3: Full analysis with fuzzing
python advanced_bug_hunter.py Contract.sol --openai-key KEY
```

### 2. Focus Areas

For specific vulnerability classes:

```python
# Modify advanced_bug_hunter.py to focus on specific areas

# For DeFi protocols - focus on:
- Novel pattern detector (economic exploits)
- Flash loan analysis in symbolic execution
- LLM economic agent

# For governance - focus on:
- Governance patterns in novel detector
- LLM adversarial agent
- Access control anomalies

# For bridges - focus on:
- Bridge patterns
- Cross-chain analysis
- Composability agent
```

### 3. Custom Property Generation

Use LLM to generate custom properties:

```python
from advanced.llm_reasoning_engine import AdvancedLLMReasoner

reasoner = AdvancedLLMReasoner(openai_key="YOUR_KEY")

vulnerabilities = [
    {"type": "flash_loan", "location": "borrow_function"},
    {"type": "price_manipulation", "location": "swap_function"}
]

harness = reasoner.generate_fuzzing_harness(contract_code, vulnerabilities)
print(harness)
```

## Real-World Examples

### Example 1: ERC-4626 Vault

```bash
python advanced_bug_hunter.py VaultContract.sol --openai-key KEY
```

**Expected findings:**
- First depositor inflation attack
- Share manipulation via donation
- Precision loss in conversion functions

### Example 2: DEX/AMM

```bash
python advanced_bug_hunter.py DexContract.sol --openai-key KEY
```

**Expected findings:**
- Sandwich attack vulnerability (no slippage)
- JIT liquidity attack
- Price oracle manipulation
- Flash loan arbitrage

### Example 3: Lending Protocol

```bash
python advanced_bug_hunter.py LendingContract.sol --openai-key KEY
```

**Expected findings:**
- Oracle price lag exploitation
- Flash loan attack vectors
- Liquidation manipulation
- Interest rate manipulation

## Troubleshooting

### High False Positive Rate

Some patterns have lower confidence - adjust thresholds:

```python
# In novel_vulnerability_patterns.py
# Filter by confidence
high_confidence_patterns = [p for p in patterns if p.confidence > 0.80]
```

### LLM API Errors

```bash
# Use local model instead
# Modify llm_reasoning_engine.py to use local LLM
# Or disable LLM:
python advanced_bug_hunter.py Contract.sol --no-llm
```

### Fuzzing Timeout

```python
# Reduce fuzzing iterations in advanced_bug_hunter.py
config = FuzzingConfig(
    strategy=strategy,
    max_iterations=1000,  # Reduce this
    max_time_seconds=300   # Or reduce timeout
)
```

## Advanced Customization

### Add Custom Patterns

In `novel_vulnerability_patterns.py`:

```python
def _detect_your_custom_pattern(self, contract_code: str) -> List[VulnerabilityPattern]:
    """Detect your custom vulnerability pattern"""
    vulnerabilities = []

    if re.search(r'your_pattern_regex', contract_code):
        vulnerabilities.append(VulnerabilityPattern(
            category=VulnerabilityCategory.ECONOMIC_EXPLOIT,
            name="your_vulnerability_name",
            description="Description of the vulnerability",
            severity="high",
            confidence=0.85,
            affected_functions=["function_name"],
            attack_vector="How to attack",
            exploit_scenario="Step-by-step exploit",
            remediation="How to fix"
        ))

    return vulnerabilities

# Add to detect_all_patterns():
self.patterns_found.extend(self._detect_your_custom_pattern(contract_code))
```

### Custom Symbolic Analysis

In `symbolic_execution_engine.py`:

```python
def analyze_your_custom_vulnerability(self, params):
    """Analyze custom vulnerability with Z3"""
    # Create symbolic variables
    var = z3.BitVec("var_name", 256)

    # Define vulnerability condition
    vuln_condition = z3.UGT(var, threshold)

    # Check satisfiability
    self.solver.push()
    self.solver.add(vuln_condition)

    if self.solver.check() == z3.sat:
        model = self.solver.model()
        # Vulnerability found!

    self.solver.pop()
```

## Performance Optimization

### Parallel Analysis

Run components in parallel:

```python
import multiprocessing

def analyze_component(component_name, contract_code):
    # Run component analysis
    pass

with multiprocessing.Pool(4) as pool:
    results = pool.starmap(analyze_component, [
        ("patterns", contract_code),
        ("anomalies", contract_code),
        ("symbolic", contract_code),
        ("fuzzing", contract_code)
    ])
```

### Caching

Cache LLM responses:

```python
import hashlib
import json

def cached_llm_call(prompt, cache_dir=".llm_cache"):
    cache_key = hashlib.sha256(prompt.encode()).hexdigest()
    cache_file = Path(cache_dir) / f"{cache_key}.json"

    if cache_file.exists():
        return json.load(open(cache_file))

    result = llm_call(prompt)
    json.dump(result, open(cache_file, 'w'))
    return result
```

## Resources

### Similar Vulnerabilities

- **Poly Network** ($611M) - Access control
- **Wormhole** ($325M) - Signature verification
- **Nomad Bridge** ($190M) - Initialization bug
- **Beanstalk** ($182M) - Flash loan governance
- **Euler Finance** ($197M) - Donation attack
- **Rari Capital** ($80M) - Cross-function reentrancy

### Further Reading

- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Trail of Bits: Building Secure Contracts](https://github.com/crytic/building-secure-contracts)
- [DeFi Security Summit Papers](https://defisecuritysummit.org/)
- [Rekt News](https://rekt.news/) - Latest exploits

## Support

For issues or questions:
1. Check the code comments
2. Review example contracts in `examples/`
3. Run with verbose logging
4. Open an issue with reproduction steps
