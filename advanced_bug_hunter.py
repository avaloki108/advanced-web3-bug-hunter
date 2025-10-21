#!/usr/bin/env python3
"""
Advanced Web3 Bug Hunter - Integration Script
Combines all advanced modules for comprehensive vulnerability discovery
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Import advanced modules
from advanced.symbolic_execution_engine import AdvancedSymbolicExecutor, SymbolicState
from advanced.novel_vulnerability_patterns import NovelPatternDetector
from advanced.behavioral_anomaly_detector import BehavioralAnomalyDetector
from advanced.llm_reasoning_engine import AdvancedLLMReasoner
from advanced.enhanced_fuzzing_orchestrator import EnhancedFuzzingOrchestrator, FuzzingConfig, FuzzingStrategy

# Import existing modules
from llm.llm_integration import LLMVulnerabilityAnalyzer
from scripts.cross_contract_tracker import CrossContractLogicTracker


class AdvancedWeb3BugHunter:
    """
    Advanced Bug Hunter integrating all cutting-edge techniques:
    - Symbolic execution with Z3
    - Novel pattern detection
    - Behavioral anomaly detection
    - Multi-agent LLM reasoning
    - Enhanced fuzzing
    """

    def __init__(self, contract_path: str, config: Dict[str, Any] = None):
        self.contract_path = Path(contract_path)
        self.config = config or {}

        # Initialize components
        self.symbolic_executor = AdvancedSymbolicExecutor()
        self.pattern_detector = NovelPatternDetector()
        self.anomaly_detector = BehavioralAnomalyDetector()
        self.llm_reasoner = AdvancedLLMReasoner(
            openai_key=self.config.get('openai_key'),
            anthropic_key=self.config.get('anthropic_key')
        )

        self.results = {
            "contract": str(self.contract_path),
            "timestamp": datetime.now().isoformat(),
            "analysis_results": {}
        }

    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline with all advanced techniques
        """
        print("="*70)
        print(" ADVANCED WEB3 BUG HUNTER - COMPREHENSIVE ANALYSIS")
        print("="*70)
        print(f"Contract: {self.contract_path}")
        print(f"Timestamp: {self.results['timestamp']}\n")

        # Read contract code
        with open(self.contract_path, 'r') as f:
            contract_code = f.read()

        contract_name = self.contract_path.stem

        # Phase 1: Pattern Detection
        print("\n[1/6] Running Novel Pattern Detection...")
        print("-" * 70)
        patterns = self.pattern_detector.detect_all_patterns(contract_code, contract_name)
        self.results["analysis_results"]["novel_patterns"] = {
            "total_patterns": len(patterns),
            "critical": len([p for p in patterns if p.severity == "critical"]),
            "high": len([p for p in patterns if p.severity == "high"]),
            "patterns": [self._serialize_pattern(p) for p in patterns]
        }
        print(f"Found {len(patterns)} novel vulnerability patterns")
        self._print_pattern_summary(patterns)

        # Phase 2: Behavioral Anomaly Detection
        print("\n[2/6] Running Behavioral Anomaly Detection...")
        print("-" * 70)
        anomalies = self.anomaly_detector.analyze_contract(contract_code, contract_name)
        self.results["analysis_results"]["anomalies"] = {
            "total_anomalies": len(anomalies),
            "critical": len([a for a in anomalies if a.severity == "critical"]),
            "high": len([a for a in anomalies if a.severity == "high"]),
            "anomalies": [self._serialize_anomaly(a) for a in anomalies]
        }
        print(f"Found {len(anomalies)} behavioral anomalies")
        self._print_anomaly_summary(anomalies)

        # Phase 3: Symbolic Execution
        print("\n[3/6] Running Symbolic Execution Analysis...")
        print("-" * 70)
        symbolic_results = self._run_symbolic_analysis(contract_code)
        self.results["analysis_results"]["symbolic_execution"] = symbolic_results
        print(f"Symbolic execution completed")

        # Phase 4: LLM Multi-Agent Reasoning
        if self.config.get('use_llm', True):
            print("\n[4/6] Running LLM Multi-Agent Reasoning...")
            print("-" * 70)
            static_results = {
                "patterns": [self._serialize_pattern(p) for p in patterns[:5]],
                "anomalies": [self._serialize_anomaly(a) for a in anomalies[:5]]
            }
            llm_results = self.llm_reasoner.analyze_contract_multi_agent(
                contract_code,
                static_results,
                contract_type=self._detect_contract_type(contract_code)
            )
            self.results["analysis_results"]["llm_reasoning"] = [
                self._serialize_llm_result(r) for r in llm_results
            ]
            print(f"LLM analysis completed with {len(llm_results)} reasoning modes")
        else:
            print("\n[4/6] Skipping LLM analysis (disabled in config)")

        # Phase 5: Enhanced Fuzzing
        if self.config.get('use_fuzzing', True):
            print("\n[5/6] Running Enhanced Fuzzing Campaign...")
            print("-" * 70)
            fuzzing_results = self._run_enhanced_fuzzing(contract_code)
            self.results["analysis_results"]["fuzzing"] = fuzzing_results
            print(f"Fuzzing campaign completed")
        else:
            print("\n[5/6] Skipping fuzzing (disabled in config)")

        # Phase 6: Generate Final Report
        print("\n[6/6] Generating Comprehensive Report...")
        print("-" * 70)
        self._generate_final_report()

        return self.results

    def _run_symbolic_analysis(self, contract_code: str) -> Dict[str, Any]:
        """Run symbolic execution analysis"""
        results = {
            "overflow_analysis": [],
            "reentrancy_analysis": [],
            "flash_loan_analysis": [],
            "oracle_manipulation": [],
            "access_control_analysis": []
        }

        try:
            # Example: Integer overflow analysis
            a = self.symbolic_executor.create_symbolic_var("userInput", VarType.UINT256, tainted=True)
            b = self.symbolic_executor.create_symbolic_var("balance", VarType.UINT256)

            overflows = self.symbolic_executor.analyze_integer_overflow_conditions(a, b, "add")
            results["overflow_analysis"] = [
                {
                    "type": v["type"],
                    "operation": v["operation"],
                    "exploitable": v["exploitable"],
                    "example_values": str(v["example_values"])
                }
                for v in overflows
            ]

            # Flash loan analysis
            initial_state = SymbolicState(
                variables={},
                constraints=[],
                balances={},
                storage={},
                call_stack=[],
                msg_sender=None,
                msg_value=None,
                block_timestamp=None,
                block_number=None
            )

            operations = [
                ("swap", {"amount_in": "flash_loan_amount"}),
                ("borrow", {"collateral_factor": 75}),
                ("liquidate", {"bonus": 10})
            ]

            flash_attacks = self.symbolic_executor.analyze_flash_loan_attack_vectors(
                initial_state,
                operations
            )

            results["flash_loan_analysis"] = [
                {
                    "type": v["type"],
                    "severity": v["severity"],
                    "description": v["description"]
                }
                for v in flash_attacks
            ]

        except Exception as e:
            results["error"] = str(e)

        return results

    def _run_enhanced_fuzzing(self, contract_code: str) -> Dict[str, Any]:
        """Run enhanced fuzzing campaign"""
        results = {"strategies": []}

        # Extract property functions from code
        import re
        properties = re.findall(r'function\s+(echidna_\w+)', contract_code)

        if not properties:
            properties = [
                "echidna_balance_conservation",
                "echidna_no_overflow",
                "echidna_access_control"
            ]

        # Run multiple fuzzing strategies
        strategies = [
            FuzzingStrategy.COVERAGE_GUIDED,
            FuzzingStrategy.MUTATION_BASED,
            FuzzingStrategy.ADVERSARIAL
        ]

        for strategy in strategies:
            config = FuzzingConfig(
                strategy=strategy,
                max_iterations=1000,
                max_time_seconds=300
            )

            orchestrator = EnhancedFuzzingOrchestrator(config)

            try:
                result = orchestrator.run_fuzzing_campaign(
                    str(self.contract_path),
                    properties
                )

                results["strategies"].append({
                    "strategy": strategy.value,
                    "iterations": result.iterations_run,
                    "coverage": result.coverage_achieved,
                    "vulnerabilities": len(result.vulnerabilities_found),
                    "crashes": result.crash_count
                })

            except Exception as e:
                results["strategies"].append({
                    "strategy": strategy.value,
                    "error": str(e)
                })

        return results

    def _detect_contract_type(self, contract_code: str) -> str:
        """Detect contract type for targeted analysis"""
        code_lower = contract_code.lower()

        if any(term in code_lower for term in ['swap', 'exchange', 'pair']):
            return 'dex'
        elif any(term in code_lower for term in ['borrow', 'lend', 'collateral']):
            return 'lending'
        elif any(term in code_lower for term in ['stake', 'reward', 'farm']):
            return 'staking'
        elif any(term in code_lower for term in ['bridge', 'relay']):
            return 'bridge'
        elif any(term in code_lower for term in ['vote', 'proposal', 'govern']):
            return 'governance'
        else:
            return 'unknown'

    def _print_pattern_summary(self, patterns):
        """Print summary of detected patterns"""
        if not patterns:
            return

        print("\nTop Findings:")
        for i, pattern in enumerate(patterns[:5], 1):
            print(f"  {i}. [{pattern.severity.upper()}] {pattern.name}")
            print(f"     {pattern.description}")

    def _print_anomaly_summary(self, anomalies):
        """Print summary of detected anomalies"""
        if not anomalies:
            return

        print("\nTop Findings:")
        for i, anomaly in enumerate(anomalies[:5], 1):
            print(f"  {i}. [{anomaly.severity.upper()}] {anomaly.name}")
            print(f"     {anomaly.description}")

    def _serialize_pattern(self, pattern) -> Dict[str, Any]:
        """Serialize pattern for JSON output"""
        return {
            "category": pattern.category.value,
            "name": pattern.name,
            "description": pattern.description,
            "severity": pattern.severity,
            "confidence": pattern.confidence,
            "attack_vector": pattern.attack_vector,
            "exploit_scenario": pattern.exploit_scenario,
            "remediation": pattern.remediation
        }

    def _serialize_anomaly(self, anomaly) -> Dict[str, Any]:
        """Serialize anomaly for JSON output"""
        return {
            "type": anomaly.anomaly_type.value,
            "name": anomaly.name,
            "description": anomaly.description,
            "severity": anomaly.severity,
            "confidence": anomaly.confidence,
            "location": anomaly.location,
            "potential_exploit": anomaly.potential_exploit,
            "remediation": anomaly.remediation
        }

    def _serialize_llm_result(self, result) -> Dict[str, Any]:
        """Serialize LLM reasoning result"""
        return {
            "mode": result.mode.value,
            "findings_count": len(result.findings),
            "attack_scenarios_count": len(result.attack_scenarios),
            "property_tests_count": len(result.property_tests),
            "confidence": result.confidence
        }

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        analysis = self.results["analysis_results"]

        print("\n" + "="*70)
        print(" COMPREHENSIVE ANALYSIS REPORT")
        print("="*70)

        # Summary statistics
        total_findings = 0
        critical_count = 0
        high_count = 0

        if "novel_patterns" in analysis:
            patterns = analysis["novel_patterns"]
            total_findings += patterns["total_patterns"]
            critical_count += patterns["critical"]
            high_count += patterns["high"]

        if "anomalies" in analysis:
            anomalies = analysis["anomalies"]
            total_findings += anomalies["total_anomalies"]
            critical_count += anomalies["critical"]
            high_count += anomalies["high"]

        print(f"\nTotal Findings: {total_findings}")
        print(f"  Critical: {critical_count}")
        print(f"  High: {high_count}")

        # Risk assessment
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 5:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        print(f"\nOverall Risk Level: {risk_level}")

        # Save to file
        output_file = Path("bug_hunter_report.json")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(f"\nDetailed report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Web3 Bug Hunter - Find novel vulnerabilities in smart contracts"
    )
    parser.add_argument("contract", help="Path to Solidity contract file")
    parser.add_argument("--openai-key", help="OpenAI API key for LLM analysis")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    parser.add_argument("--no-fuzzing", action="store_true", help="Disable fuzzing")
    parser.add_argument("--output", "-o", help="Output file for results (default: bug_hunter_report.json)")

    args = parser.parse_args()

    config = {
        "openai_key": args.openai_key,
        "use_llm": not args.no_llm,
        "use_fuzzing": not args.no_fuzzing,
        "output_file": args.output or "bug_hunter_report.json"
    }

    # Check if contract exists
    if not Path(args.contract).exists():
        print(f"Error: Contract file not found: {args.contract}")
        sys.exit(1)

    # Run analysis
    hunter = AdvancedWeb3BugHunter(args.contract, config)
    results = hunter.run_comprehensive_analysis()

    print("\n" + "="*70)
    print(" ANALYSIS COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()
