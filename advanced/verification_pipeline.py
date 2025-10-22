"""
Verification Pipeline - Multi-Layered Hypothesis Verification
Combines static analysis, symbolic execution, and dynamic testing
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import json


class VerificationLayer(Enum):
    """Different layers of verification"""
    STATIC_ANALYSIS = "static_analysis"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DYNAMIC_TESTING = "dynamic_testing"
    POC_EXECUTION = "poc_execution"


@dataclass
class VerificationResult:
    """Result from a single verification layer"""
    layer: VerificationLayer
    hypothesis_id: str
    verified: bool
    confidence: float  # 0.0-1.0
    evidence: List[str]
    execution_time: float
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)
    

@dataclass
class AggregatedVerification:
    """Aggregated verification result across all layers"""
    hypothesis_id: str
    layer_results: Dict[VerificationLayer, VerificationResult]
    final_confidence: float
    verification_status: str  # verified, rejected, uncertain
    recommendation: str
    severity_adjusted: str
    timestamp: str


class VerificationPipeline:
    """
    Multi-layered verification pipeline
    Validates hypotheses through progressive verification stages
    """
    
    def __init__(self,
                 static_analyzer=None,
                 symbolic_executor=None,
                 dynamic_tester=None,
                 poc_generator=None):
        self.static_analyzer = static_analyzer
        self.symbolic_executor = symbolic_executor
        self.dynamic_tester = dynamic_tester
        self.poc_generator = poc_generator
        
        self.verification_history: List[AggregatedVerification] = []
        self.layer_weights = {
            VerificationLayer.STATIC_ANALYSIS: 0.2,
            VerificationLayer.SYMBOLIC_EXECUTION: 0.3,
            VerificationLayer.DYNAMIC_TESTING: 0.25,
            VerificationLayer.POC_EXECUTION: 0.25
        }
        
    def verify_hypothesis(self,
                         hypothesis: Any,
                         contract_code: str,
                         run_all_layers: bool = True) -> AggregatedVerification:
        """
        Verify a hypothesis through multiple layers
        
        Args:
            hypothesis: VulnerabilityHypothesis object
            contract_code: Source code to analyze
            run_all_layers: Whether to run all layers or stop early on rejection
        """
        layer_results = {}
        
        # Layer 1: Static Analysis
        static_result = self._verify_static_analysis(hypothesis, contract_code)
        layer_results[VerificationLayer.STATIC_ANALYSIS] = static_result
        
        if not run_all_layers and not static_result.verified:
            return self._aggregate_results(hypothesis, layer_results)
        
        # Layer 2: Symbolic Execution
        if self.symbolic_executor:
            symbolic_result = self._verify_symbolic_execution(hypothesis, contract_code)
            layer_results[VerificationLayer.SYMBOLIC_EXECUTION] = symbolic_result
            
            if not run_all_layers and not symbolic_result.verified:
                return self._aggregate_results(hypothesis, layer_results)
        
        # Layer 3: Dynamic Testing
        if self.dynamic_tester:
            dynamic_result = self._verify_dynamic_testing(hypothesis, contract_code)
            layer_results[VerificationLayer.DYNAMIC_TESTING] = dynamic_result
            
            if not run_all_layers and not dynamic_result.verified:
                return self._aggregate_results(hypothesis, layer_results)
        
        # Layer 4: PoC Execution
        if self.poc_generator and static_result.verified:
            poc_result = self._verify_poc_execution(hypothesis, contract_code)
            layer_results[VerificationLayer.POC_EXECUTION] = poc_result
        
        # Aggregate results
        aggregated = self._aggregate_results(hypothesis, layer_results)
        self.verification_history.append(aggregated)
        
        return aggregated
    
    def verify_batch(self,
                    hypotheses: List[Any],
                    contract_code: str,
                    parallel: bool = False) -> List[AggregatedVerification]:
        """
        Verify multiple hypotheses
        """
        results = []
        
        for hypothesis in hypotheses:
            result = self.verify_hypothesis(hypothesis, contract_code, run_all_layers=True)
            results.append(result)
        
        return results
    
    def _verify_static_analysis(self,
                               hypothesis: Any,
                               contract_code: str) -> VerificationResult:
        """
        Layer 1: Static analysis verification
        Uses pattern matching and code analysis
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}
        
        try:
            # Check for code patterns related to hypothesis
            if hasattr(hypothesis, 'type'):
                hypothesis_type = hypothesis.type.value if hasattr(hypothesis.type, 'value') else str(hypothesis.type)
                
                # Reentrancy checks
                if 'reentrancy' in hypothesis_type.lower():
                    has_external_call = 'call' in contract_code.lower()
                    has_state_change = any(word in contract_code for word in ['balance', 'transfer', '='])
                    no_protection = 'nonReentrant' not in contract_code and 'ReentrancyGuard' not in contract_code
                    
                    if has_external_call and has_state_change and no_protection:
                        verified = True
                        confidence = 0.7
                        evidence.append("External calls found without reentrancy protection")
                        evidence.append("State changes detected after external calls")
                    
                    details['has_external_call'] = has_external_call
                    details['has_protection'] = not no_protection
                
                # Oracle manipulation checks
                elif 'oracle' in hypothesis_type.lower():
                    has_oracle_call = any(word in contract_code for word in ['oracle', 'latestAnswer', 'getPrice'])
                    no_timestamp_check = 'timestamp' not in contract_code.lower()
                    no_staleness_check = 'updatedAt' not in contract_code
                    
                    if has_oracle_call and (no_timestamp_check or no_staleness_check):
                        verified = True
                        confidence = 0.6
                        evidence.append("Oracle price feed used")
                        if no_staleness_check:
                            evidence.append("No staleness check detected")
                    
                    details['has_oracle'] = has_oracle_call
                    details['has_staleness_check'] = not no_staleness_check
                
                # Cross-contract checks
                elif 'cross_contract' in hypothesis_type.lower():
                    has_external_interface = any(word in contract_code for word in ['interface', 'IERC', 'external'])
                    has_untrusted_call = '.call' in contract_code or 'delegatecall' in contract_code
                    
                    if has_external_interface or has_untrusted_call:
                        verified = True
                        confidence = 0.5
                        evidence.append("External contract interactions detected")
                    
                    details['has_external_interface'] = has_external_interface
                
                # Access control checks
                elif 'access' in hypothesis_type.lower():
                    has_privileged_functions = any(word in contract_code for word in ['onlyOwner', 'onlyAdmin', 'admin'])
                    has_modifier = 'modifier' in contract_code
                    
                    if not has_modifier and not has_privileged_functions:
                        verified = True
                        confidence = 0.6
                        evidence.append("No access control modifiers found")
                
                # Edge case checks
                elif 'edge' in hypothesis_type.lower():
                    has_division = '/' in contract_code
                    has_zero_check = 'require' in contract_code.lower() or 'assert' in contract_code.lower()
                    
                    if has_division and not has_zero_check:
                        verified = True
                        confidence = 0.4
                        evidence.append("Division operations without checks")
                    
                    details['has_division'] = has_division
                    details['has_checks'] = has_zero_check
        
        except Exception as e:
            evidence.append(f"Static analysis error: {str(e)}")
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return VerificationResult(
            layer=VerificationLayer.STATIC_ANALYSIS,
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details
        )
    
    def _verify_symbolic_execution(self,
                                   hypothesis: Any,
                                   contract_code: str) -> VerificationResult:
        """
        Layer 2: Symbolic execution verification
        Uses Z3 solver to prove exploitability
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}
        
        try:
            if self.symbolic_executor:
                # Run symbolic execution
                # This is a simplified version - actual implementation would be more complex
                result = self.symbolic_executor.analyze_contract(contract_code[:1000])
                
                if hasattr(result, 'vulnerabilities') and result.vulnerabilities:
                    verified = True
                    confidence = 0.8
                    evidence.append("Symbolic execution found exploitable path")
                    evidence.extend([v.get('description', '') for v in result.vulnerabilities[:3]])
                    details['symbolic_paths'] = len(getattr(result, 'paths', []))
            else:
                # Fallback: Pattern-based symbolic reasoning
                if hasattr(hypothesis, 'type'):
                    hypothesis_type = hypothesis.type.value if hasattr(hypothesis.type, 'value') else str(hypothesis.type)
                    
                    # Simplified checks
                    if 'reentrancy' in hypothesis_type.lower():
                        # Look for call patterns
                        if 'call{value:' in contract_code or '.call(' in contract_code:
                            verified = True
                            confidence = 0.6
                            evidence.append("Potential execution path for reentrancy found")
                
        except Exception as e:
            evidence.append(f"Symbolic execution error: {str(e)}")
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return VerificationResult(
            layer=VerificationLayer.SYMBOLIC_EXECUTION,
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details
        )
    
    def _verify_dynamic_testing(self,
                               hypothesis: Any,
                               contract_code: str) -> VerificationResult:
        """
        Layer 3: Dynamic testing verification
        Simulates attack scenarios
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}
        
        # Placeholder for dynamic testing
        # In production, this would deploy to test environment and execute attack scenarios
        try:
            # Simplified dynamic check
            if hasattr(hypothesis, 'attack_scenario') and hypothesis.attack_scenario:
                # Check if attack scenario is feasible
                scenario = hypothesis.attack_scenario.lower()
                
                if any(word in scenario for word in ['call', 'transfer', 'send']):
                    verified = True
                    confidence = 0.5
                    evidence.append("Attack scenario appears feasible")
        
        except Exception as e:
            evidence.append(f"Dynamic testing error: {str(e)}")
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return VerificationResult(
            layer=VerificationLayer.DYNAMIC_TESTING,
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details
        )
    
    def _verify_poc_execution(self,
                             hypothesis: Any,
                             contract_code: str) -> VerificationResult:
        """
        Layer 4: PoC execution verification
        Generates and executes proof of concept
        """
        start_time = datetime.now()
        verified = False
        confidence = 0.0
        evidence = []
        details = {}
        
        try:
            if self.poc_generator:
                # Generate and execute PoC
                poc_result = self.poc_generator.generate_and_execute(hypothesis, contract_code)
                
                if poc_result.get('success', False):
                    verified = True
                    confidence = 0.95  # High confidence if PoC executes successfully
                    evidence.append("PoC executed successfully")
                    evidence.append(f"Exploit demonstrated: {poc_result.get('description', '')}")
                    details['poc_output'] = poc_result.get('output', '')
            else:
                # Placeholder without actual PoC generator
                evidence.append("PoC generator not configured")
        
        except Exception as e:
            evidence.append(f"PoC execution error: {str(e)}")
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return VerificationResult(
            layer=VerificationLayer.POC_EXECUTION,
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            verified=verified,
            confidence=confidence,
            evidence=evidence,
            execution_time=execution_time,
            timestamp=datetime.now().isoformat(),
            details=details
        )
    
    def _aggregate_results(self,
                          hypothesis: Any,
                          layer_results: Dict[VerificationLayer, VerificationResult]) -> AggregatedVerification:
        """
        Aggregate verification results from all layers
        Calculate final confidence score
        """
        # Calculate weighted confidence score
        total_weight = 0.0
        weighted_confidence = 0.0
        
        for layer, result in layer_results.items():
            weight = self.layer_weights.get(layer, 0.25)
            total_weight += weight
            if result.verified:
                weighted_confidence += result.confidence * weight
        
        final_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.0
        
        # Determine verification status
        if final_confidence >= 0.7:
            status = "verified"
            recommendation = "High confidence vulnerability - prioritize remediation"
        elif final_confidence >= 0.4:
            status = "uncertain"
            recommendation = "Moderate confidence - manual review recommended"
        else:
            status = "rejected"
            recommendation = "Low confidence - likely false positive"
        
        # Adjust severity based on confidence
        original_severity = getattr(hypothesis, 'severity', 'medium')
        if final_confidence < 0.5:
            severity_adjusted = "low" if original_severity != "critical" else "medium"
        else:
            severity_adjusted = original_severity
        
        return AggregatedVerification(
            hypothesis_id=getattr(hypothesis, 'id', 'unknown'),
            layer_results=layer_results,
            final_confidence=final_confidence,
            verification_status=status,
            recommendation=recommendation,
            severity_adjusted=severity_adjusted,
            timestamp=datetime.now().isoformat()
        )
    
    def update_layer_weights(self, new_weights: Dict[VerificationLayer, float]):
        """Update weights for different verification layers"""
        total = sum(new_weights.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError("Weights must sum to 1.0")
        
        self.layer_weights.update(new_weights)
    
    def get_verification_stats(self) -> Dict[str, Any]:
        """Get statistics about verification pipeline"""
        if not self.verification_history:
            return {
                "total_verifications": 0,
                "verified_count": 0,
                "rejected_count": 0,
                "uncertain_count": 0
            }
        
        verified = len([v for v in self.verification_history if v.verification_status == "verified"])
        rejected = len([v for v in self.verification_history if v.verification_status == "rejected"])
        uncertain = len([v for v in self.verification_history if v.verification_status == "uncertain"])
        
        avg_confidence = sum(v.final_confidence for v in self.verification_history) / len(self.verification_history)
        
        # Layer statistics
        layer_stats = {}
        for layer in VerificationLayer:
            layer_results = [
                v.layer_results.get(layer) 
                for v in self.verification_history 
                if layer in v.layer_results
            ]
            if layer_results:
                layer_stats[layer.value] = {
                    "total": len(layer_results),
                    "verified": len([r for r in layer_results if r.verified]),
                    "avg_confidence": sum(r.confidence for r in layer_results) / len(layer_results),
                    "avg_execution_time": sum(r.execution_time for r in layer_results) / len(layer_results)
                }
        
        return {
            "total_verifications": len(self.verification_history),
            "verified_count": verified,
            "rejected_count": rejected,
            "uncertain_count": uncertain,
            "avg_confidence": avg_confidence,
            "layer_statistics": layer_stats,
            "current_weights": {k.value: v for k, v in self.layer_weights.items()}
        }
    
    def export_verification_report(self, filepath: str):
        """Export verification results to JSON"""
        report = {
            "statistics": self.get_verification_stats(),
            "verification_history": [
                {
                    "hypothesis_id": v.hypothesis_id,
                    "final_confidence": v.final_confidence,
                    "status": v.verification_status,
                    "recommendation": v.recommendation,
                    "severity_adjusted": v.severity_adjusted,
                    "timestamp": v.timestamp,
                    "layers": {
                        layer.value: {
                            "verified": result.verified,
                            "confidence": result.confidence,
                            "evidence": result.evidence,
                            "execution_time": result.execution_time
                        }
                        for layer, result in v.layer_results.items()
                    }
                }
                for v in self.verification_history
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Verification report exported to {filepath}")
