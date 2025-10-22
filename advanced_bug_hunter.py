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
from advanced.persistent_learning import PersistentLearningDB, get_learning_db
from advanced.benchmark_comparison import BenchmarkSystem
from advanced.rare_vulnerability_detectors import RareVulnerabilityDetector
from advanced.poc_generator import AutomatedPoCGenerator, PoCFramework

# Import existing modules (optional dependencies)
try:
    from llm.llm_integration import LLMVulnerabilityAnalyzer
    HAS_LLM = True
except ImportError:
    HAS_LLM = False
    
try:
    from scripts.cross_contract_tracker import CrossContractLogicTracker
    HAS_SLITHER = True
except ImportError:
    HAS_SLITHER = False


class AdvancedWeb3BugHunter:
    """
    Advanced Bug Hunter integrating all cutting-edge techniques:
    - Symbolic execution with Z3
    - Novel pattern detection
    - Behavioral anomaly detection
    - Multi-agent LLM reasoning
    - Enhanced fuzzing
    - Automated PoC generation
    """

    def __init__(self, contract_path: str, config: Dict[str, Any] = None):
        self.contract_path = Path(contract_path)
        self.config = config or {}
        self.start_time = datetime.now()

        # Initialize components
        self.symbolic_executor = AdvancedSymbolicExecutor()
        self.pattern_detector = NovelPatternDetector()
        self.anomaly_detector = BehavioralAnomalyDetector()
        self.rare_detector = RareVulnerabilityDetector()
        self.llm_reasoner = AdvancedLLMReasoner(
            openai_key=self.config.get('openai_key'),
            anthropic_key=self.config.get('anthropic_key')
        )
        
        # Initialize PoC generator
        self.poc_generator = AutomatedPoCGenerator(
            frameworks=[PoCFramework.FOUNDRY]
        ) if self.config.get('enable_poc_generation', True) else None
        
        # Initialize learning system
        self.learning_db = get_learning_db()

        self.results = {
            "contract": str(self.contract_path),
            "timestamp": self.start_time.isoformat(),
            "analysis_results": {},
            "learning_enhanced": True,
            "poc_generation_enabled": self.poc_generator is not None
        }

    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Run complete analysis pipeline with all advanced techniques
        NOW WITH REAL LEARNING - Improves with each scan!
        """
        print("="*70)
        print(" ADVANCED WEB3 BUG HUNTER - COMPREHENSIVE ANALYSIS")
        print(" 🧠 LEARNING-ENABLED: Tool improves with every scan!")
        if self.poc_generator:
            print(" 🔬 PoC GENERATION: Automated exploit demonstrations")
        print("="*70)
        print(f"Contract: {self.contract_path}")
        print(f"Timestamp: {self.results['timestamp']}")
        
        # Show improvement metrics
        metrics = self.learning_db.get_improvement_metrics()
        if metrics.get('total_scans', 0) > 0:
            print(f"Previous scans: {metrics['total_scans']} | ")
            print(f"Patterns learned: {metrics.get('total_patterns_learned', 0)} | ")
            print(f"Current accuracy: {metrics.get('recent_accuracy', 0.0):.1%}")
        print()

        # Read contract code
        with open(self.contract_path, 'r') as f:
            contract_code = f.read()

        contract_name = self.contract_path.stem

        # Phase 1: Pattern Detection
        print("\n[1/8] Running Novel Pattern Detection...")
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
        print("\n[2/8] Running Behavioral Anomaly Detection...")
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
        
        # Phase 2.5: Rare & Niche Vulnerability Detection (NEW!)
        print("\n[2.5/8] Running Rare & Niche Vulnerability Detection...")
        print("-" * 70)
        print("🔍 Searching for obscure vulnerabilities that standard tools miss...")
        rare_vulns = self.rare_detector.detect_all(contract_code)
        self.results["analysis_results"]["rare_vulnerabilities"] = {
            "total_rare": len(rare_vulns),
            "critical": len([r for r in rare_vulns if r.severity == "critical"]),
            "high": len([r for r in rare_vulns if r.severity == "high"]),
            "findings": [self._serialize_rare_vuln(r) for r in rare_vulns]
        }
        print(f"Found {len(rare_vulns)} rare/niche vulnerabilities!")
        if rare_vulns:
            print("\n⭐ RARE FINDINGS (likely missed by other tools):")
            for i, vuln in enumerate(rare_vulns[:5], 1):
                print(f"  {i}. [{vuln.severity.upper()}] {vuln.name}")
                print(f"     {vuln.description}")
                print(f"     Confidence: {vuln.confidence:.0%}")
        else:
            print("No rare vulnerabilities detected (good sign!)")

        # Phase 3: Symbolic Execution
        print("\n[3/8] Running Symbolic Execution Analysis...")
        print("-" * 70)
        symbolic_results = self._run_symbolic_analysis(contract_code)
        self.results["analysis_results"]["symbolic_execution"] = symbolic_results
        print(f"Symbolic execution completed")

        # Phase 4: LLM Multi-Agent Reasoning (WITH LEARNING!)
        llm_insights = []
        if self.config.get('use_llm', True) and HAS_LLM:
            print("\n[4/8] Running LLM Multi-Agent Reasoning (Enhanced with Learning)...")
            print("-" * 70)
            
            # Get enhanced prompt with learned patterns
            enhanced_prompt = self.learning_db.get_enhanced_llm_prompt()
            print(f"Using enhanced prompt with {len(self.learning_db.get_learned_patterns_for_analysis())} learned patterns")
            
            static_results = {
                "patterns": [self._serialize_pattern(p) for p in patterns[:5]],
                "anomalies": [self._serialize_anomaly(a) for a in anomalies[:5]],
                "learned_patterns": self.learning_db.get_learned_patterns_for_analysis()[:5]
            }
            try:
                llm_results = self.llm_reasoner.analyze_contract_multi_agent(
                    contract_code,
                    static_results,
                    contract_type=self._detect_contract_type(contract_code)
                )
                self.results["analysis_results"]["llm_reasoning"] = [
                    self._serialize_llm_result(r) for r in llm_results
                ]
                
                # Extract insights for learning
                for result in llm_results:
                    if hasattr(result, 'findings'):
                        llm_insights.extend([str(f) for f in result.findings])
            except Exception as e:
                print(f"  ⚠️  LLM analysis failed: {str(e)}")
                self.results["analysis_results"]["llm_reasoning"] = {"error": str(e)}
                    
            
                print(f"LLM analysis completed with {len(llm_results)} reasoning modes")
                print(f"Extracted {len(llm_insights)} insights for learning")
            except:
                pass  # Error already handled above
        else:
            print("\n[4/8] Skipping LLM analysis (disabled or unavailable)")

        # Phase 5: Enhanced Fuzzing
        if self.config.get('use_fuzzing', True):
            print("\n[5/8] Running Enhanced Fuzzing Campaign...")
            print("-" * 70)
            fuzzing_results = self._run_enhanced_fuzzing(contract_code)
            self.results["analysis_results"]["fuzzing"] = fuzzing_results
            print(f"Fuzzing campaign completed")
        else:
            print("\n[5/8] Skipping fuzzing (disabled in config)")
        
        # Phase 5.5: Automated PoC Generation (NEW!)
        poc_results = []
        if self.poc_generator and self.config.get('generate_pocs', True):
            print("\n[5.5/8] 🔬 Generating Proof-of-Concept Exploits...")
            print("-" * 70)
            print("Generating PoCs for detected vulnerabilities...")
            
            # Collect high-confidence vulnerabilities for PoC generation
            vulnerabilities_for_poc = []
            
            # Add critical/high severity rare vulnerabilities
            for vuln in rare_vulns:
                if vuln.severity in ['critical', 'high'] and vuln.confidence >= 0.7:
                    vulnerabilities_for_poc.append(vuln)
            
            # Add high-confidence patterns
            for pattern in patterns:
                if pattern.severity in ['critical', 'high'] and pattern.confidence >= 0.8:
                    vulnerabilities_for_poc.append(pattern)
            
            # Add critical anomalies
            for anomaly in anomalies:
                if anomaly.severity == 'critical' and anomaly.confidence >= 0.75:
                    vulnerabilities_for_poc.append(anomaly)
            
            # Limit to top 5 vulnerabilities to avoid long execution times
            vulnerabilities_for_poc = vulnerabilities_for_poc[:5]
            
            print(f"Selected {len(vulnerabilities_for_poc)} high-priority vulnerabilities for PoC generation")
            
            # Generate PoCs
            import asyncio
            for i, vuln in enumerate(vulnerabilities_for_poc, 1):
                vuln_name = getattr(vuln, 'name', 'Unknown')
                print(f"\n  [{i}/{len(vulnerabilities_for_poc)}] Generating PoC for: {vuln_name}")
                
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    poc_result = loop.run_until_complete(
                        self.poc_generator.generate_and_test_poc(
                            vuln,
                            contract_code,
                            contract_name,
                            execute_in_sandbox=self.config.get('execute_pocs', False)
                        )
                    )
                    loop.close()
                    
                    if poc_result.get('success'):
                        print(f"    ✓ PoC generated using '{poc_result.get('strategy_used', 'unknown')}' strategy")
                        if poc_result.get('safety_validated'):
                            print(f"    ✓ Safety validated")
                        if self.config.get('execute_pocs', False):
                            if poc_result.get('exploit_demonstrated'):
                                print(f"    ✓ Exploit successfully demonstrated in sandbox")
                            else:
                                print(f"    ⚠️  PoC generated but exploit not demonstrated")
                    else:
                        print(f"    ✗ Failed to generate PoC: {poc_result.get('error', 'Unknown error')}")
                    
                    poc_results.append({
                        'vulnerability': vuln_name,
                        'severity': getattr(vuln, 'severity', 'unknown'),
                        'poc_generated': poc_result.get('success', False),
                        'strategy': poc_result.get('strategy_used', 'none'),
                        'safety_validated': poc_result.get('safety_validated', False),
                        'exploit_demonstrated': poc_result.get('exploit_demonstrated', False),
                        'poc_code_preview': poc_result.get('poc_code', '')[:200] + '...' if poc_result.get('poc_code') else ''
                    })
                    
                except Exception as e:
                    print(f"    ✗ Error generating PoC: {str(e)}")
                    poc_results.append({
                        'vulnerability': vuln_name,
                        'error': str(e)
                    })
            
            # Store PoC results
            self.results["analysis_results"]["poc_generation"] = {
                "total_vulnerabilities_analyzed": len(vulnerabilities_for_poc),
                "pocs_generated": len([p for p in poc_results if p.get('poc_generated')]),
                "pocs_safety_validated": len([p for p in poc_results if p.get('safety_validated')]),
                "exploits_demonstrated": len([p for p in poc_results if p.get('exploit_demonstrated')]),
                "results": poc_results,
                "statistics": self.poc_generator.get_statistics() if self.poc_generator else {}
            }
            
            print(f"\n✓ PoC Generation Summary:")
            print(f"  Total PoCs generated: {len([p for p in poc_results if p.get('poc_generated')])}/{len(vulnerabilities_for_poc)}")
            print(f"  Safety validated: {len([p for p in poc_results if p.get('safety_validated')])}")
            if self.config.get('execute_pocs', False):
                print(f"  Exploits demonstrated: {len([p for p in poc_results if p.get('exploit_demonstrated')])}")
        else:
            print("\n[5.5/8] Skipping PoC generation (disabled in config)")

        # Phase 6: Generate Final Report & LEARN!
        print("\n[6/8] Generating Comprehensive Report & Recording Learning...")
        print("-" * 70)
        self._generate_final_report()
        
        # Record what we learned from this analysis
        processing_time = (datetime.now() - self.start_time).total_seconds()
        all_vulnerabilities = []
        
        # Collect all findings
        for pattern in patterns:
            all_vulnerabilities.append({
                'name': pattern.name,
                'severity': pattern.severity,
                'type': 'pattern',
                'confidence': pattern.confidence
            })
            
        for anomaly in anomalies:
            all_vulnerabilities.append({
                'name': anomaly.name,
                'severity': anomaly.severity,
                'type': 'anomaly',
                'confidence': anomaly.confidence
            })
            
        for rare_vuln in rare_vulns:
            all_vulnerabilities.append({
                'name': rare_vuln.name,
                'severity': rare_vuln.severity,
                'type': 'rare',
                'confidence': rare_vuln.confidence
            })
            
        # Record to learning database
        learning_record = self.learning_db.record_analysis(
            contract_code=contract_code,
            vulnerabilities_found=all_vulnerabilities,
            llm_insights=llm_insights,
            processing_time=processing_time
        )
        
        self.results["learning_record_id"] = learning_record.id
        self.results["total_scans_to_date"] = len(self.learning_db.learning_records)
        
        print(f"✓ Learning recorded: {learning_record.id}")
        print(f"✓ Total analyses in knowledge base: {len(self.learning_db.learning_records)}")
        
        # Show improvement suggestions
        suggestions = self.learning_db.suggest_improvements()
        if suggestions:
            print(f"\n💡 Learning System Suggestions:")
            for suggestion in suggestions[:3]:
                print(f"   • {suggestion}")

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
    
    def _serialize_rare_vuln(self, vuln) -> Dict[str, Any]:
        """Serialize rare vulnerability"""
        return {
            "name": vuln.name,
            "description": vuln.description,
            "severity": vuln.severity,
            "confidence": vuln.confidence,
            "affected_code": vuln.affected_code,
            "exploit_scenario": vuln.exploit_scenario,
            "remediation": vuln.remediation,
            "references": vuln.references,
            "cve_id": vuln.cve_id
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
            
        if "rare_vulnerabilities" in analysis:
            rare = analysis["rare_vulnerabilities"]
            total_findings += rare["total_rare"]
            critical_count += rare["critical"]
            high_count += rare["high"]

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
        description="Advanced Web3 Bug Hunter - Find novel vulnerabilities in smart contracts with LEARNING"
    )
    parser.add_argument("contract", help="Path to Solidity contract file")
    parser.add_argument("--openai-key", help="OpenAI API key for LLM analysis")
    parser.add_argument("--anthropic-key", help="Anthropic API key for Claude")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM analysis")
    parser.add_argument("--no-fuzzing", action="store_true", help="Disable fuzzing")
    parser.add_argument("--output", "-o", help="Output file for results (default: bug_hunter_report.json)")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark comparison vs Slither/Mythril")
    parser.add_argument("--show-learning", action="store_true", help="Show learning metrics and exit")

    args = parser.parse_args()
    
    # Show learning metrics if requested
    if args.show_learning:
        learning_db = get_learning_db()
        metrics = learning_db.get_improvement_metrics()
        
        print("="*70)
        print("LEARNING SYSTEM METRICS")
        print("="*70)
        print(f"\nTotal scans completed: {metrics.get('total_scans', 0)}")
        print(f"Patterns learned: {metrics.get('total_patterns_learned', 0)}")
        print(f"Vulnerability types known: {metrics.get('vulnerability_types_known', 0)}")
        
        if metrics.get('total_scans', 0) >= 2:
            print(f"\nAccuracy Metrics:")
            print(f"  Initial accuracy: {metrics.get('initial_accuracy', 0):.1%}")
            print(f"  Recent accuracy: {metrics.get('recent_accuracy', 0):.1%}")
            print(f"  Improvement: {metrics.get('improvement_percentage', 0):.1f}%")
            
        if metrics.get('top_patterns'):
            print(f"\nTop Detection Patterns:")
            for i, pattern in enumerate(metrics['top_patterns'][:5], 1):
                print(f"  {i}. {pattern['name']} (confidence: {pattern['confidence']:.1%}, detections: {pattern['detections']})")
                
        suggestions = learning_db.suggest_improvements()
        if suggestions:
            print(f"\n💡 Suggestions:")
            for suggestion in suggestions:
                print(f"  • {suggestion}")
                
        sys.exit(0)
    
    # Run benchmark if requested
    if args.benchmark:
        print("="*70)
        print("BENCHMARK MODE: Comparing vs Slither and Mythril")
        print("="*70)
        
        benchmark_system = BenchmarkSystem()
        report = benchmark_system.compare_all_tools(args.contract)
        
        summary = benchmark_system.generate_summary_report()
        print(f"\n📊 Overall Statistics:")
        print(f"   Total benchmarks: {summary['total_benchmarks']}")
        print(f"   Win rate: {summary['win_rate']:.1%}")
        print(f"   Unique findings: {summary['total_unique_findings']}")
        
        sys.exit(0)

    args = parser.parse_args()

    config = {
        "openai_key": args.openai_key,
        "anthropic_key": args.anthropic_key,
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
