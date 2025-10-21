"""
Advanced LLM Reasoning Engine for Vulnerability Discovery
Multi-agent approach with specialized reasoning modules
Combines GPT-4, Claude, and local models for comprehensive analysis
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import os


class ReasoningMode(Enum):
    ADVERSARIAL = "adversarial"  # Think like an attacker
    DEFENSIVE = "defensive"  # Think like an auditor
    ECONOMIC = "economic"  # Analyze economic incentives
    COMPOSABILITY = "composability"  # Cross-protocol interactions
    FORMAL = "formal"  # Formal verification reasoning


@dataclass
class ReasoningResult:
    """Result from LLM reasoning"""
    mode: ReasoningMode
    findings: List[Dict[str, Any]]
    attack_scenarios: List[str]
    property_tests: List[str]
    confidence: float
    reasoning_chain: List[str]  # Chain of thought
    references: List[str] = field(default_factory=list)


class AdvancedLLMReasoner:
    """
    Multi-agent LLM reasoning system for vulnerability discovery
    Uses chain-of-thought, adversarial thinking, and domain expertise
    """

    def __init__(self, openai_key: Optional[str] = None, anthropic_key: Optional[str] = None):
        self.openai_key = openai_key or os.getenv("OPENAI_API_KEY")
        self.anthropic_key = anthropic_key or os.getenv("ANTHROPIC_API_KEY")
        self.reasoning_history: List[ReasoningResult] = []

    def analyze_contract_multi_agent(self,
                                    contract_code: str,
                                    static_analysis_results: Dict[str, Any],
                                    contract_type: str = "unknown") -> List[ReasoningResult]:
        """
        Run multiple reasoning agents in parallel for comprehensive analysis
        """
        results = []

        # Agent 1: Adversarial Reasoning
        results.append(self._adversarial_reasoning(contract_code, static_analysis_results))

        # Agent 2: Economic Analysis
        results.append(self._economic_reasoning(contract_code, contract_type))

        # Agent 3: Composability Analysis
        results.append(self._composability_reasoning(contract_code))

        # Agent 4: Formal Verification
        results.append(self._formal_reasoning(contract_code))

        # Agent 5: Pattern Matching
        results.append(self._pattern_reasoning(contract_code, static_analysis_results))

        # Synthesize results
        synthesized = self._synthesize_findings(results)
        results.append(synthesized)

        self.reasoning_history.extend(results)
        return results

    def _adversarial_reasoning(self,
                              contract_code: str,
                              static_results: Dict[str, Any]) -> ReasoningResult:
        """
        Think like an attacker - find novel exploit paths
        """
        prompt = self._build_adversarial_prompt(contract_code, static_results)

        # This would call GPT-4/Claude in production
        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.7)

        findings = self._parse_adversarial_response(response)

        return ReasoningResult(
            mode=ReasoningMode.ADVERSARIAL,
            findings=findings,
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.75,
            reasoning_chain=self._extract_reasoning_chain(response)
        )

    def query_llm(self, prompt: str, model: str = "gpt-4", temperature: float = 0.7) -> str:
        """
        Query LLM with proper error handling
        Supports OpenAI, Anthropic (Claude), and XAI (Grok)
        """
        try:
            # Try OpenAI first
            if self.openai_key:
                from openai import OpenAI
                client = OpenAI(api_key=self.openai_key)
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature
                )
                return response.choices[0].message.content
                
            # Try Anthropic/Claude
            elif self.anthropic_key:
                import anthropic
                client = anthropic.Anthropic(api_key=self.anthropic_key)
                message = client.messages.create(
                    model="claude-3-opus-20240229",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )
                return message.content[0].text
                
            # Try XAI/Grok
            elif os.getenv("XAI_API_KEY"):
                from openai import OpenAI
                client = OpenAI(
                    api_key=os.getenv("XAI_API_KEY"),
                    base_url="https://api.x.ai/v1"
                )
                response = client.chat.completions.create(
                    model="grok-beta",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2000,
                    temperature=temperature
                )
                return response.choices[0].message.content
            else:
                return "LLM API key not configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or XAI_API_KEY."
                
        except Exception as e:
            return f"LLM Error: {str(e)}"

    def _build_adversarial_prompt(self, contract_code: str, static_results: Dict[str, Any]) -> str:
        """Build prompt for adversarial reasoning"""
        return f"""You are an expert Web3 security researcher and ethical hacker.
Your goal is to find novel vulnerabilities by thinking like an attacker.

CONTRACT CODE:
```solidity
{contract_code[:3000]}  # Truncate for token limits
```

STATIC ANALYSIS RESULTS:
{json.dumps(static_results, indent=2)[:1000]}

ADVERSARIAL REASONING FRAMEWORK:
1. Identify all attack surfaces (external functions, state variables, etc.)
2. Map trust boundaries and privilege levels
3. Trace data flow from user inputs to critical operations
4. Identify composability risks with external protocols
5. Consider multi-transaction attack sequences
6. Think about economic incentives and game theory

SPECIFIC ATTACK VECTORS TO CONSIDER:
- Flash loan attacks (manipulate state with borrowed capital)
- Oracle manipulation (exploit price feeds)
- Governance attacks (flash loan voting, proposal griefing)
- MEV extraction (sandwich attacks, front-running)
- Cross-function reentrancy (exploit state inconsistencies)
- ERC-4626 share inflation
- First depositor attacks
- Donation attacks
- Time-based exploits
- Cross-chain bridge attacks
- Reward calculation manipulations

For each potential vulnerability, provide:
1. Vulnerability type and location
2. Attack scenario (step-by-step)
3. Preconditions needed
4. Expected profit/impact
5. Difficulty of exploitation
6. Remediation suggestion

Think deeply and creatively. Focus on logic flaws that automated tools miss.
"""

    def _economic_reasoning(self, contract_code: str, contract_type: str) -> ReasoningResult:
        """Analyze economic incentives and game theory"""
        prompt = f"""You are a Web3 economic security expert.
Analyze this {contract_type} contract for economic vulnerabilities and misaligned incentives.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

ECONOMIC ANALYSIS FRAMEWORK:
1. Identify all economic actors and their incentives
2. Map value flows (tokens, fees, rewards)
3. Find misaligned incentives
4. Consider game-theoretic equilibria
5. Analyze attack profitability

KEY QUESTIONS:
- Can an attacker profit risk-free?
- Are there scenarios where attacking is more profitable than honest participation?
- Can economic parameters be manipulated?
- Are there economic feedback loops that could spiral?
- What happens at economic extremes (very high/low prices, liquidity, etc.)?

SPECIFIC ECONOMIC ATTACKS:
- Flash loan attacks (zero-risk capital)
- Liquidity manipulation
- Price oracle manipulation
- Reward gaming
- Fee extraction
- Governance token manipulation
- Collateral attacks

Provide:
1. Economic vulnerabilities found
2. Profit calculation for attacks
3. Risk/reward analysis for attacker
4. Economic parameter recommendations
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.5)

        return ReasoningResult(
            mode=ReasoningMode.ECONOMIC,
            findings=self._parse_economic_response(response),
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.70,
            reasoning_chain=self._extract_reasoning_chain(response)
        )

    def _composability_reasoning(self, contract_code: str) -> ReasoningResult:
        """Analyze cross-protocol composability risks"""
        prompt = f"""You are an expert in DeFi composability and protocol interactions.
Analyze how this contract interacts with external protocols and identify composability risks.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

COMPOSABILITY ANALYSIS:
1. Identify all external protocol dependencies
2. Map protocol interaction patterns
3. Find assumptions about external protocol behavior
4. Identify shared state or resources
5. Consider multi-protocol attack sequences

COMPOSABILITY RISKS:
- Read-only reentrancy across protocols
- Price oracle inconsistencies
- Liquidity assumptions
- Protocol upgrade risks
- Cross-protocol MEV
- Shared collateral risks
- Circular dependencies

For each risk:
1. External protocols involved
2. Interaction pattern
3. Failure scenarios
4. Attack scenarios
5. Mitigation strategies
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.6)

        return ReasoningResult(
            mode=ReasoningMode.COMPOSABILITY,
            findings=self._parse_composability_response(response),
            attack_scenarios=self._extract_attack_scenarios(response),
            property_tests=[],
            confidence=0.65,
            reasoning_chain=self._extract_reasoning_chain(response)
        )

    def _formal_reasoning(self, contract_code: str) -> ReasoningResult:
        """Generate formal properties and invariants"""
        prompt = f"""You are a formal verification expert.
Analyze this contract and suggest formal properties that should hold.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

FORMAL PROPERTY GENERATION:
1. Identify state invariants (must always be true)
2. Define preconditions and postconditions for functions
3. Specify temporal properties
4. Define conservation laws
5. Identify safety and liveness properties

PROPERTY CATEGORIES:
- Balance conservation (sum of balances = total supply)
- Access control (only authorized can execute)
- State transitions (valid state machine)
- Arithmetic safety (no overflow/underflow)
- Economic invariants (collateral >= debt)

For each property, provide:
1. Property description (English)
2. Formal specification (Solidity/Certora)
3. Importance/criticality
4. How to test it

Output formal properties suitable for Echidna, Certora, or manual testing.
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.3)

        return ReasoningResult(
            mode=ReasoningMode.FORMAL,
            findings=[],
            attack_scenarios=[],
            property_tests=self._extract_property_tests(response),
            confidence=0.80,
            reasoning_chain=self._extract_reasoning_chain(response)
        )

    def _pattern_reasoning(self,
                          contract_code: str,
                          static_results: Dict[str, Any]) -> ReasoningResult:
        """Match against known vulnerability patterns"""
        prompt = f"""You are a vulnerability pattern expert.
Compare this contract against known vulnerability patterns and historical exploits.

CONTRACT CODE:
```solidity
{contract_code[:2500]}
```

STATIC ANALYSIS FINDINGS:
{json.dumps(static_results, indent=2)[:1000]}

KNOWN PATTERNS TO CHECK:
1. Historical DeFi Hacks:
   - Poly Network (access control)
   - Wormhole (signature verification)
   - Ronin Bridge (validator compromise)
   - Nomad Bridge (initialization bug)
   - Cream Finance (reentrancy)

2. Common Patterns:
   - Unchecked external calls
   - Integer overflow/underflow
   - Reentrancy (classic, cross-function, read-only)
   - Front-running
   - Access control issues
   - Oracle manipulation

3. DeFi-Specific:
   - ERC-4626 inflation
   - AMM manipulation
   - Flash loan attacks
   - Governance exploits

For each pattern match:
1. Pattern name and reference
2. How it manifests in this code
3. Severity and exploitability
4. Historical precedent
5. Recommended fix
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.4)

        return ReasoningResult(
            mode=ReasoningMode.DEFENSIVE,
            findings=self._parse_pattern_response(response),
            attack_scenarios=[],
            property_tests=[],
            confidence=0.85,
            reasoning_chain=self._extract_reasoning_chain(response),
            references=self._extract_references(response)
        )

    def _synthesize_findings(self, results: List[ReasoningResult]) -> ReasoningResult:
        """Synthesize findings from all agents"""
        all_findings = []
        all_scenarios = []
        all_properties = []

        for result in results:
            all_findings.extend(result.findings)
            all_scenarios.extend(result.attack_scenarios)
            all_properties.extend(result.property_tests)

        # Remove duplicates and rank by confidence
        unique_findings = self._deduplicate_findings(all_findings)
        ranked_findings = sorted(unique_findings, key=lambda x: x.get('confidence', 0), reverse=True)

        return ReasoningResult(
            mode=ReasoningMode.DEFENSIVE,
            findings=ranked_findings[:20],  # Top 20
            attack_scenarios=list(set(all_scenarios)),
            property_tests=list(set(all_properties)),
            confidence=0.80,
            reasoning_chain=["Synthesized from multiple reasoning agents"]
        )

    def _call_llm(self, prompt: str, model: str = "gpt-4-turbo", temperature: float = 0.7) -> str:
        """
        Call LLM API (OpenAI, Anthropic, or local)
        In production, this would make actual API calls
        """
        # Placeholder - in production, this would call actual LLM APIs
        mock_response = f"""
        MOCK LLM RESPONSE (Replace with actual API call)

        Based on analysis of the provided contract:

        FINDINGS:
        1. Potential reentrancy in withdraw function
        2. Missing slippage protection in swap
        3. Oracle price could be manipulated

        ATTACK SCENARIOS:
        - Flash loan attack to manipulate price oracle
        - Sandwich attack on unprotected swaps
        - Cross-function reentrancy between withdraw and deposit

        PROPERTY TESTS:
        - echidna_balance_conservation: totalSupply == sum(balances)
        - echidna_no_negative_balance: forall user, balance[user] >= 0
        - echidna_price_bounds: price >= MIN_PRICE && price <= MAX_PRICE

        REASONING:
        The contract uses block.timestamp for time-dependent logic, which can be
        manipulated by miners within a 15-second window. Combined with the lack
        of slippage protection, this creates an MEV opportunity.

        REFERENCES:
        - Similar vulnerability in Project X (2023)
        - See: https://example.com/vulnerability-report
        """

        return mock_response

    def _parse_adversarial_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response for adversarial findings"""
        # In production, use more sophisticated parsing
        findings = []

        # Extract findings from response (simplified)
        if "reentrancy" in response.lower():
            findings.append({
                "type": "reentrancy",
                "severity": "high",
                "confidence": 0.8,
                "description": "Potential reentrancy vulnerability",
                "location": "withdraw function"
            })

        if "slippage" in response.lower():
            findings.append({
                "type": "slippage_missing",
                "severity": "medium",
                "confidence": 0.7,
                "description": "Missing slippage protection",
                "location": "swap function"
            })

        return findings

    def _parse_economic_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse economic analysis response"""
        return []  # Simplified for demo

    def _parse_composability_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse composability analysis response"""
        return []  # Simplified for demo

    def _parse_pattern_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse pattern matching response"""
        return []  # Simplified for demo

    def _extract_attack_scenarios(self, response: str) -> List[str]:
        """Extract attack scenarios from response"""
        scenarios = []

        # Simple extraction
        lines = response.split('\n')
        for i, line in enumerate(lines):
            if 'attack' in line.lower() and 'scenario' in line.lower():
                # Collect next few lines
                scenario = '\n'.join(lines[i:i+5])
                scenarios.append(scenario)

        return scenarios

    def _extract_property_tests(self, response: str) -> List[str]:
        """Extract property test specifications"""
        properties = []

        # Extract echidna-style properties
        import re
        echidna_pattern = r'echidna_\w+.*'
        properties = re.findall(echidna_pattern, response)

        return properties

    def _extract_reasoning_chain(self, response: str) -> List[str]:
        """Extract chain of thought reasoning"""
        chains = []

        lines = response.split('\n')
        for line in lines:
            if line.strip() and (
                'because' in line.lower() or
                'therefore' in line.lower() or
                'this means' in line.lower()
            ):
                chains.append(line.strip())

        return chains

    def _extract_references(self, response: str) -> List[str]:
        """Extract references to known vulnerabilities"""
        import re
        url_pattern = r'https?://[^\s]+'
        refs = re.findall(url_pattern, response)
        return refs

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            # Create fingerprint
            fingerprint = (
                finding.get('type', ''),
                finding.get('location', '')
            )

            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(finding)

        return unique

    def generate_fuzzing_harness(self,
                                contract_code: str,
                                vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate targeted fuzzing harness based on LLM findings"""
        prompt = f"""Generate Echidna fuzzing properties to test the following vulnerabilities:

CONTRACT:
{contract_code[:2000]}

SUSPECTED VULNERABILITIES:
{json.dumps(vulnerabilities, indent=2)}

Generate:
1. Property functions (echidna_*) that would detect these vulnerabilities
2. Helper functions to set up test conditions
3. Custom test cases for edge cases

Make properties specific and targeted to the suspected vulnerabilities.
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.2)
        return response

    def explain_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """Generate detailed explanation of vulnerability for report"""
        prompt = f"""Explain this vulnerability in detail for a security report:

VULNERABILITY:
{json.dumps(vulnerability, indent=2)}

Provide:
1. Technical explanation
2. Proof-of-concept code
3. Impact assessment
4. Remediation steps
5. Similar historical vulnerabilities

Write for a technical audience (developers and auditors).
"""

        response = self._call_llm(prompt, model="gpt-4-turbo", temperature=0.3)
        return response


def demonstrate_llm_reasoning():
    """Demonstrate advanced LLM reasoning"""

    reasoner = AdvancedLLMReasoner()

    sample_contract = """
    contract VulnerableVault {
        mapping(address => uint256) public balances;
        uint256 public totalSupply;

        function deposit() public payable {
            balances[msg.sender] += msg.value;
            totalSupply += msg.value;
        }

        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            msg.sender.call{value: amount}("");  // Reentrancy!
            balances[msg.sender] -= amount;  // State update after call
            totalSupply -= amount;
        }

        function getPrice() public view returns (uint256) {
            // Using spot price - vulnerable to manipulation!
            return dex.getReserves();
        }
    }
    """

    static_results = {
        "detectors": {
            "reentrancy": ["withdraw"],
            "unprotected_call": ["withdraw"]
        }
    }

    print("=== Advanced LLM Reasoning Analysis ===\n")

    results = reasoner.analyze_contract_multi_agent(
        sample_contract,
        static_results,
        "vault"
    )

    for result in results:
        print(f"\n{'='*60}")
        print(f"REASONING MODE: {result.mode.value}")
        print(f"Confidence: {result.confidence}")
        print(f"{'='*60}")

        if result.findings:
            print(f"\nFindings ({len(result.findings)}):")
            for finding in result.findings:
                print(f"  - {finding}")

        if result.attack_scenarios:
            print(f"\nAttack Scenarios ({len(result.attack_scenarios)}):")
            for scenario in result.attack_scenarios[:3]:
                print(f"  {scenario}")

        if result.property_tests:
            print(f"\nProperty Tests ({len(result.property_tests)}):")
            for prop in result.property_tests[:5]:
                print(f"  {prop}")

    # Generate fuzzing harness
    print("\n" + "="*60)
    print("FUZZING HARNESS GENERATION")
    print("="*60)

    harness = reasoner.generate_fuzzing_harness(sample_contract, results[0].findings)
    print(harness[:500])

    return results


if __name__ == "__main__":
    results = demonstrate_llm_reasoning()
    print(f"\n\nTotal reasoning modes: {len(results)}")
