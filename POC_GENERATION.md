# Automated PoC Generation System

## Overview

The Automated PoC (Proof-of-Concept) Generation System creates safe, runnable exploit demonstrations for detected vulnerabilities. PoCs execute in sandboxed environments (Foundry) without transferring real funds, validating hypotheses through concrete exploitation.

## Features

### 🔒 Safety Framework

All generated PoCs undergo comprehensive safety validation:

- **No mainnet interaction**: Prevents connection to production networks
- **No real fund transfers**: Ensures test-only execution
- **No malicious external calls**: Blocks suspicious patterns
- **Test framework validation**: Requires proper Foundry/Hardhat setup
- **Private key protection**: Detects and blocks credential exposure

### 📝 Multi-Strategy Generation

#### 1. Template-Based (Fast, Reliable)
- Pre-built templates for common vulnerabilities
- Supports: reentrancy, oracle manipulation, flash loans, access control, integer overflow
- Fast generation with high reliability
- Automatically filled with contract-specific details

#### 2. LLM-Assisted (Creative, Flexible)
- Uses AI to generate custom PoCs
- Handles novel or complex vulnerabilities
- Iteratively refined for compilation and execution
- Falls back to templates if unavailable

#### 3. Hybrid (Best of Both)
- Combines template structure with LLM customization
- Balances reliability and flexibility
- Automatically selected for rare vulnerabilities

### 🏃 Sandboxed Execution

PoCs can be executed in isolated environments:

- **Foundry support**: Primary execution framework
- **Hardhat support**: Alternative framework (coming soon)
- **Timeout protection**: Prevents hanging processes
- **Resource limits**: Safe execution boundaries
- **Detailed output**: Gas usage, state changes, execution traces

## Usage

### Basic Usage

```python
from advanced.poc_generator import AutomatedPoCGenerator

# Initialize generator
generator = AutomatedPoCGenerator()

# Generate PoC for a vulnerability
result = await generator.generate_and_test_poc(
    vulnerability=detected_vuln,
    contract_code=contract_source,
    contract_name="VulnerableContract",
    execute_in_sandbox=False  # Set to True to run in Foundry
)

# Check results
if result['success']:
    print(f"PoC generated using {result['strategy_used']} strategy")
    print(f"Safety validated: {result['safety_validated']}")
    print(result['poc_code'])
```

### Integration with Analysis Pipeline

The PoC generator is automatically integrated into the main analysis flow:

```python
from advanced_bug_hunter import AdvancedWeb3BugHunter

# Enable PoC generation in config
config = {
    'enable_poc_generation': True,
    'generate_pocs': True,
    'execute_pocs': False  # Set to True to execute in sandbox
}

hunter = AdvancedWeb3BugHunter("contract.sol", config)
results = hunter.run_comprehensive_analysis()

# Access PoC results
poc_results = results['analysis_results']['poc_generation']
```

### Manual Safety Validation

```python
from advanced.poc_generator import SafetyValidator

validator = SafetyValidator()

# Validate PoC code
result = validator.validate(poc_code)

if result['safe']:
    print("✓ PoC is safe to execute")
else:
    print("✗ Safety concerns:")
    for warning in result['warnings']:
        print(f"  {warning}")
```

## Supported Vulnerability Types

### Current Templates

1. **Reentrancy**
   - Classic reentrancy attacks
   - Cross-function reentrancy
   - Attacker contract generation

2. **Oracle Manipulation**
   - Price oracle manipulation
   - Mock oracle injection
   - Price impact verification

3. **Flash Loan Attacks**
   - Flash loan borrowing
   - Exploit execution
   - Profit calculation

4. **Access Control**
   - Unauthorized function calls
   - Privilege escalation
   - Permission bypass

5. **Integer Overflow/Underflow**
   - Arithmetic overflow exploitation
   - Balance manipulation
   - Wrapped arithmetic abuse

### Generic Template

For vulnerabilities without specific templates, a generic template is used that can be manually customized.

## Configuration Options

### Main Analysis Config

```python
config = {
    # Enable/disable PoC generation
    'enable_poc_generation': True,
    
    # Generate PoCs for detected vulnerabilities
    'generate_pocs': True,
    
    # Execute PoCs in sandbox (requires Foundry)
    'execute_pocs': False,
    
    # Use LLM for PoC generation (requires API keys)
    'use_llm': True,
}
```

### PoC Generation Filters

Only high-priority vulnerabilities are selected for PoC generation:

- Critical/High severity
- Confidence >= 70%
- Limited to top 5 vulnerabilities (configurable)

## Output Format

### PoC Generation Results

```json
{
  "poc_generation": {
    "total_vulnerabilities_analyzed": 3,
    "pocs_generated": 3,
    "pocs_safety_validated": 3,
    "exploits_demonstrated": 2,
    "results": [
      {
        "vulnerability": "Reentrancy Attack",
        "severity": "critical",
        "poc_generated": true,
        "strategy": "template",
        "safety_validated": true,
        "exploit_demonstrated": true,
        "poc_code_preview": "// SPDX-License-Identifier: MIT..."
      }
    ],
    "statistics": {
      "total_generated": 3,
      "safety_validated": 3,
      "average_execution_time": 2.5
    }
  }
}
```

## Requirements

### Core Requirements

- Python 3.8+
- Foundry (for PoC execution)

### Optional Requirements

- OpenAI/Anthropic API keys (for LLM-assisted generation)
- Hardhat (alternative framework)

### Installing Foundry

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify installation
forge --version
```

## Safety Guarantees

The PoC generation system provides multiple layers of safety:

1. **Code Analysis**: Static analysis of generated code
2. **Pattern Detection**: Blocks known malicious patterns
3. **Framework Validation**: Ensures test framework usage
4. **Sandbox Execution**: Isolated execution environment
5. **No Real Assets**: Test-only funds and addresses

### Safety Checks

- ✅ No mainnet RPC URLs
- ✅ No production addresses
- ✅ No private key exposure
- ✅ No real fund transfers
- ✅ Test framework required
- ✅ Sandbox execution only

## Examples

### Example 1: Generate PoC for Reentrancy

```python
from advanced.poc_generator import PoCGenerator, PoCFramework

generator = PoCGenerator(PoCFramework.FOUNDRY)

# Define vulnerability
class ReentrancyVuln:
    name = "Reentrancy in withdraw()"
    type = "reentrancy"
    severity = "critical"
    confidence = 0.95
    description = "withdraw() function vulnerable to reentrancy"
    exploit_scenario = "Attacker can drain contract funds"

vuln = ReentrancyVuln()
contract = open("VulnerableVault.sol").read()

# Generate PoC
poc_code = generator.generate_poc(vuln, contract, "VulnerableVault")

# Save to file
with open("test/Exploit.t.sol", "w") as f:
    f.write(poc_code)

print("✓ PoC generated: test/Exploit.t.sol")
```

### Example 2: Execute PoC in Sandbox

```python
import asyncio
from advanced.poc_generator import SandboxExecutor, PoCFramework

async def run_poc():
    executor = SandboxExecutor(PoCFramework.FOUNDRY)
    
    result = await executor.execute_poc(
        poc_code=generated_poc,
        contract_code=contract_source,
        contract_name="VulnerableContract"
    )
    
    if result['success']:
        print("✓ PoC executed successfully")
        print(f"Gas used: {result['gas_used']}")
        print(f"Exploit demonstrated: {result['exploit_demonstrated']}")
    else:
        print(f"✗ Execution failed: {result['error']}")

asyncio.run(run_poc())
```

### Example 3: Complete Workflow

See `examples/poc_generation_demo.py` for a complete demonstration of:

- Safety validation
- Template-based generation
- Multi-vulnerability support
- Automated strategy selection
- Statistics tracking

## Best Practices

### 1. Always Validate Safety

```python
validator = SafetyValidator()
result = validator.validate(poc_code)

if not result['safe']:
    print("⚠️  Manual review required")
    for warning in result['warnings']:
        print(f"  {warning}")
```

### 2. Test Before Execution

```python
# Generate first
poc = generator.generate_poc(vuln, contract, name)

# Validate
if validator.validate(poc)['safe']:
    # Then execute
    result = await executor.execute_poc(poc, contract, name)
```

### 3. Review Generated Code

Always review generated PoCs before using them, especially for:
- Complex vulnerabilities
- Custom contract logic
- Production testing

### 4. Use Appropriate Strategy

- **Template**: Common vulnerabilities (reentrancy, oracle, etc.)
- **LLM**: Novel or complex vulnerabilities
- **Hybrid**: Rare vulnerabilities requiring customization
- **Auto**: Let the system choose

## Troubleshooting

### PoC Generation Fails

**Problem**: PoC generation returns error

**Solutions**:
- Check if vulnerability type is supported
- Verify contract code is valid Solidity
- Review error message for specific issues
- Try different strategy (template vs LLM)

### Safety Validation Fails

**Problem**: Generated PoC fails safety checks

**Solutions**:
- Review warnings to understand issues
- Manually modify PoC if needed
- Report issue if templates are incorrectly flagged

### Sandbox Execution Fails

**Problem**: PoC execution in sandbox fails

**Solutions**:
- Verify Foundry is installed: `forge --version`
- Check contract compiles: `forge build`
- Review execution error output
- Increase timeout for complex tests

### No Foundry Installed

**Problem**: Sandbox execution unavailable

**Solutions**:
- Install Foundry: `curl -L https://foundry.paradigm.xyz | bash`
- Or disable sandbox execution: `execute_pocs: False`
- Or use manual testing with generated PoC code

## Limitations

### Current Limitations

1. **Foundry Only**: Hardhat support coming soon
2. **Template Coverage**: Not all vulnerability types have templates
3. **LLM Dependency**: Advanced generation requires API keys
4. **Execution Environment**: Requires Foundry installation
5. **Complex Contracts**: May need manual PoC customization

### Future Enhancements

- [ ] Hardhat framework support
- [ ] More vulnerability templates
- [ ] Better LLM prompt engineering
- [ ] Automated PoC refinement
- [ ] Multi-contract PoC support
- [ ] Gas optimization analysis
- [ ] Exploit profitability calculation

## Contributing

To add new vulnerability templates:

1. Create template in `_initialize_templates()`
2. Add mapping in `_map_hypothesis_to_vuln_type()`
3. Test with `test_poc_generator.py`
4. Document in this guide

## Support

For issues or questions:

1. Check this documentation
2. Review examples in `examples/poc_generation_demo.py`
3. Run tests: `python tests/test_poc_generator.py`
4. Check GitHub issues

## References

- [Foundry Documentation](https://book.getfoundry.sh/)
- [Solidity Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Smart Contract Vulnerabilities](https://swcregistry.io/)
