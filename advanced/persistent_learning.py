"""
Persistent Learning System - True incremental learning from every analysis
Tracks what the tool learns, improves accuracy over time, and persists knowledge
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class LearningRecord:
    """Record of what was learned from an analysis"""
    id: str
    timestamp: str
    contract_hash: str
    vulnerabilities_found: List[str]
    false_positives_marked: List[str]
    patterns_extracted: List[Dict[str, Any]]
    accuracy_score: float
    processing_time: float
    llm_insights: List[str]
    
    
@dataclass  
class PatternEffectiveness:
    """Track how effective each vulnerability pattern is"""
    pattern_name: str
    times_detected: int
    true_positives: int
    false_positives: int
    last_updated: str
    confidence_score: float


@dataclass
class HypothesisQualityMetrics:
    """Track quality of AI-generated hypotheses"""
    hypothesis_type: str
    total_generated: int
    verified_count: int
    rejected_count: int
    avg_initial_confidence: float
    avg_final_confidence: float
    success_rate: float
    last_updated: str
    

class PersistentLearningDB:
    """
    Persistent learning database that improves with each scan
    Stores all learnings and uses them to improve future scans
    """
    
    def __init__(self, db_path: str = "learned_knowledge.json"):
        self.db_path = Path(db_path)
        self.learning_records: List[LearningRecord] = []
        self.pattern_effectiveness: Dict[str, PatternEffectiveness] = {}
        self.vulnerability_corpus: Dict[str, List[str]] = {}  # Type -> examples
        self.accuracy_history: List[float] = []
        self.hypothesis_metrics: Dict[str, HypothesisQualityMetrics] = {}  # Track hypothesis quality
        self.prompt_effectiveness: Dict[str, float] = {}  # Track prompt effectiveness
        
        # NEW: Adaptive learning fields
        self.prompt_performance: Dict[str, Any] = {}  # Detailed prompt performance tracking
        self.verification_weights: Dict[str, Any] = {}  # Verification layer weights
        self.hypothesis_quality_trends: Dict[str, List[float]] = {}  # Quality trends over time
        self.user_feedback_log: List[Dict[str, Any]] = []  # User feedback history
        
        self._load_database()
        
    def _load_database(self):
        """Load existing learning database"""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    
                # Load learning records
                if 'learning_records' in data:
                    self.learning_records = [
                        LearningRecord(**record) 
                        for record in data['learning_records']
                    ]
                    
                # Load pattern effectiveness
                if 'pattern_effectiveness' in data:
                    self.pattern_effectiveness = {
                        name: PatternEffectiveness(**stats)
                        for name, stats in data['pattern_effectiveness'].items()
                    }
                    
                # Load vulnerability corpus
                if 'vulnerability_corpus' in data:
                    self.vulnerability_corpus = data['vulnerability_corpus']
                    
                # Load accuracy history
                if 'accuracy_history' in data:
                    self.accuracy_history = data['accuracy_history']
                
                # Load hypothesis metrics
                if 'hypothesis_metrics' in data:
                    self.hypothesis_metrics = {
                        name: HypothesisQualityMetrics(**metrics)
                        for name, metrics in data['hypothesis_metrics'].items()
                    }
                
                # Load prompt effectiveness
                if 'prompt_effectiveness' in data:
                    self.prompt_effectiveness = data['prompt_effectiveness']
                
                # Load adaptive learning fields (NEW)
                if 'prompt_performance' in data:
                    self.prompt_performance = data['prompt_performance']
                
                if 'verification_weights' in data:
                    self.verification_weights = data['verification_weights']
                
                if 'hypothesis_quality_trends' in data:
                    self.hypothesis_quality_trends = data['hypothesis_quality_trends']
                
                if 'user_feedback_log' in data:
                    self.user_feedback_log = data['user_feedback_log']
                    
                print(f"✓ Loaded learning database: {len(self.learning_records)} records")
            except Exception as e:
                print(f"Warning: Could not load learning database: {e}")
                
    def save_database(self):
        """Persist all learning data"""
        try:
            data = {
                'learning_records': [asdict(r) for r in self.learning_records],
                'pattern_effectiveness': {
                    name: asdict(stats) 
                    for name, stats in self.pattern_effectiveness.items()
                },
                'vulnerability_corpus': self.vulnerability_corpus,
                'accuracy_history': self.accuracy_history,
                'hypothesis_metrics': {
                    name: asdict(metrics)
                    for name, metrics in self.hypothesis_metrics.items()
                },
                'prompt_effectiveness': self.prompt_effectiveness,
                # NEW: Adaptive learning fields
                'prompt_performance': self.prompt_performance,
                'verification_weights': self.verification_weights,
                'hypothesis_quality_trends': self.hypothesis_quality_trends,
                'user_feedback_log': self.user_feedback_log,
                'last_updated': datetime.now().isoformat(),
                'total_scans': len(self.learning_records)
            }
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            print(f"✓ Saved learning database: {len(self.learning_records)} records")
        except Exception as e:
            print(f"Error saving database: {e}")
            
    def record_analysis(self, 
                       contract_code: str,
                       vulnerabilities_found: List[Dict[str, Any]],
                       llm_insights: List[str],
                       processing_time: float,
                       user_feedback: Optional[Dict[str, Any]] = None) -> LearningRecord:
        """
        Record what was learned from this analysis
        This is called after EVERY scan to improve the system
        """
        # Generate unique ID for this analysis
        contract_hash = hashlib.sha256(contract_code.encode()).hexdigest()[:16]
        record_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{contract_hash[:8]}"
        
        # Extract vulnerability types
        vuln_types = [v.get('name', v.get('type', 'unknown')) for v in vulnerabilities_found]
        
        # Calculate accuracy if user provided feedback
        accuracy = 1.0  # Default if no feedback
        false_positives = []
        
        if user_feedback:
            false_positives = user_feedback.get('false_positives', [])
            confirmed = user_feedback.get('confirmed', len(vulnerabilities_found))
            total = len(vulnerabilities_found)
            accuracy = confirmed / total if total > 0 else 1.0
            
        # Extract patterns from findings
        patterns_extracted = self._extract_patterns_from_findings(vulnerabilities_found)
        
        # Create learning record
        record = LearningRecord(
            id=record_id,
            timestamp=datetime.now().isoformat(),
            contract_hash=contract_hash,
            vulnerabilities_found=vuln_types,
            false_positives_marked=false_positives,
            patterns_extracted=patterns_extracted,
            accuracy_score=accuracy,
            processing_time=processing_time,
            llm_insights=llm_insights
        )
        
        # Store record
        self.learning_records.append(record)
        self.accuracy_history.append(accuracy)
        
        # Update pattern effectiveness
        self._update_pattern_effectiveness(vuln_types, false_positives)
        
        # Add to vulnerability corpus
        for vuln_type in vuln_types:
            if vuln_type not in self.vulnerability_corpus:
                self.vulnerability_corpus[vuln_type] = []
            # Store code snippet for this vulnerability type
            snippet = contract_code[:200]  # First 200 chars as example
            if snippet not in self.vulnerability_corpus[vuln_type]:
                self.vulnerability_corpus[vuln_type].append(snippet)
                
        # Save to disk
        self.save_database()
        
        return record
        
    def _extract_patterns_from_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract reusable patterns from vulnerability findings"""
        patterns = []
        
        for vuln in vulnerabilities:
            pattern = {
                'type': vuln.get('name', vuln.get('type', 'unknown')),
                'severity': vuln.get('severity', 'medium'),
                'indicators': [],
                'detection_strategy': vuln.get('detection_strategy', 'static_analysis')
            }
            
            # Extract code patterns if available
            if 'affected_code' in vuln:
                pattern['code_signature'] = vuln['affected_code'][:100]
                
            # Extract function patterns
            if 'affected_functions' in vuln:
                pattern['function_signatures'] = vuln['affected_functions']
                
            patterns.append(pattern)
            
        return patterns
        
    def _update_pattern_effectiveness(self, detected: List[str], false_positives: List[str]):
        """Update effectiveness tracking for each detection pattern"""
        for pattern_name in detected:
            if pattern_name not in self.pattern_effectiveness:
                self.pattern_effectiveness[pattern_name] = PatternEffectiveness(
                    pattern_name=pattern_name,
                    times_detected=0,
                    true_positives=0,
                    false_positives=0,
                    last_updated=datetime.now().isoformat(),
                    confidence_score=0.5
                )
                
            stats = self.pattern_effectiveness[pattern_name]
            stats.times_detected += 1
            
            if pattern_name in false_positives:
                stats.false_positives += 1
            else:
                stats.true_positives += 1
                
            # Update confidence score based on accuracy
            total = stats.true_positives + stats.false_positives
            stats.confidence_score = stats.true_positives / total if total > 0 else 0.5
            stats.last_updated = datetime.now().isoformat()
            
    def get_learned_patterns_for_analysis(self) -> List[Dict[str, Any]]:
        """
        Get all learned patterns to use in next analysis
        Returns patterns sorted by effectiveness
        """
        patterns = []
        
        for pattern_name, stats in self.pattern_effectiveness.items():
            if stats.confidence_score >= 0.5:  # Only include effective patterns
                patterns.append({
                    'name': pattern_name,
                    'confidence': stats.confidence_score,
                    'examples': self.vulnerability_corpus.get(pattern_name, [])[:3],
                    'times_detected': stats.times_detected
                })
                
        # Sort by confidence
        patterns.sort(key=lambda x: x['confidence'], reverse=True)
        return patterns
        
    def get_improvement_metrics(self) -> Dict[str, Any]:
        """Get metrics showing how the tool has improved over time"""
        if len(self.accuracy_history) < 2:
            return {
                'scans_completed': len(self.learning_records),
                'improvement': 'insufficient_data'
            }
            
        # Calculate improvement over time
        recent_accuracy = sum(self.accuracy_history[-10:]) / min(10, len(self.accuracy_history))
        initial_accuracy = sum(self.accuracy_history[:10]) / min(10, len(self.accuracy_history))
        improvement = recent_accuracy - initial_accuracy
        
        # Find most effective patterns
        top_patterns = sorted(
            self.pattern_effectiveness.values(),
            key=lambda x: x.confidence_score,
            reverse=True
        )[:5]
        
        return {
            'total_scans': len(self.learning_records),
            'average_accuracy': sum(self.accuracy_history) / len(self.accuracy_history),
            'recent_accuracy': recent_accuracy,
            'initial_accuracy': initial_accuracy,
            'improvement_percentage': improvement * 100,
            'total_patterns_learned': len(self.pattern_effectiveness),
            'top_patterns': [
                {
                    'name': p.pattern_name,
                    'confidence': p.confidence_score,
                    'detections': p.times_detected
                }
                for p in top_patterns
            ],
            'vulnerability_types_known': len(self.vulnerability_corpus)
        }
        
    def get_enhanced_llm_prompt(self) -> str:
        """
        Generate enhanced LLM prompt with all learned patterns
        This makes the LLM smarter with each scan
        """
        prompt = """You are an advanced smart contract auditor with continuously learning capabilities.

Based on previous analyses, pay special attention to these vulnerability patterns:

"""
        
        patterns = self.get_learned_patterns_for_analysis()
        
        for i, pattern in enumerate(patterns[:10], 1):  # Top 10 patterns
            prompt += f"\n{i}. {pattern['name']} (Confidence: {pattern['confidence']:.2f})"
            if pattern['examples']:
                prompt += f"\n   Example indicators: {pattern['examples'][0][:100]}..."
                
        prompt += """

Use these learned patterns to:
1. Detect similar vulnerabilities in the current contract
2. Identify variations of known patterns
3. Look for novel vulnerabilities that match these categories
4. Consider edge cases based on past findings

Provide detailed analysis with specific code references.
"""
        
        return prompt
    
    def track_hypothesis_quality(self,
                                hypothesis_type: str,
                                initial_confidence: float,
                                final_confidence: float,
                                verified: bool):
        """
        Track quality metrics for AI-generated hypotheses
        Helps improve prompt strategies over time
        """
        if hypothesis_type not in self.hypothesis_metrics:
            self.hypothesis_metrics[hypothesis_type] = HypothesisQualityMetrics(
                hypothesis_type=hypothesis_type,
                total_generated=0,
                verified_count=0,
                rejected_count=0,
                avg_initial_confidence=0.0,
                avg_final_confidence=0.0,
                success_rate=0.0,
                last_updated=datetime.now().isoformat()
            )
        
        metrics = self.hypothesis_metrics[hypothesis_type]
        
        # Update counts
        metrics.total_generated += 1
        if verified:
            metrics.verified_count += 1
        else:
            metrics.rejected_count += 1
        
        # Update averages (running average)
        total = metrics.total_generated
        metrics.avg_initial_confidence = (
            (metrics.avg_initial_confidence * (total - 1) + initial_confidence) / total
        )
        metrics.avg_final_confidence = (
            (metrics.avg_final_confidence * (total - 1) + final_confidence) / total
        )
        
        # Update success rate
        metrics.success_rate = metrics.verified_count / metrics.total_generated
        metrics.last_updated = datetime.now().isoformat()
        
    def update_prompt_effectiveness(self, prompt_id: str, effectiveness_score: float):
        """
        Track effectiveness of specific prompts
        Helps identify which prompts generate best hypotheses
        """
        self.prompt_effectiveness[prompt_id] = effectiveness_score
        
    def get_hypothesis_quality_report(self) -> Dict[str, Any]:
        """Get report on hypothesis generation quality"""
        if not self.hypothesis_metrics:
            return {
                "total_hypotheses": 0,
                "message": "No hypothesis data available yet"
            }
        
        total_hypotheses = sum(m.total_generated for m in self.hypothesis_metrics.values())
        total_verified = sum(m.verified_count for m in self.hypothesis_metrics.values())
        
        return {
            "total_hypotheses_generated": total_hypotheses,
            "total_verified": total_verified,
            "overall_success_rate": total_verified / total_hypotheses if total_hypotheses > 0 else 0.0,
            "by_type": {
                name: {
                    "total": m.total_generated,
                    "verified": m.verified_count,
                    "success_rate": m.success_rate,
                    "avg_initial_confidence": m.avg_initial_confidence,
                    "avg_final_confidence": m.avg_final_confidence,
                    "confidence_improvement": m.avg_final_confidence - m.avg_initial_confidence
                }
                for name, m in self.hypothesis_metrics.items()
            },
            "best_performing_types": sorted(
                [
                    (name, m.success_rate) 
                    for name, m in self.hypothesis_metrics.items()
                ],
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    def get_prompt_recommendations(self) -> Dict[str, Any]:
        """Get recommendations for prompt optimization"""
        if not self.hypothesis_metrics:
            return {"message": "Insufficient data for recommendations"}
        
        recommendations = []
        
        # Analyze hypothesis types
        for name, metrics in self.hypothesis_metrics.items():
            if metrics.total_generated < 5:
                continue
                
            # Low success rate - adjust temperature/prompt
            if metrics.success_rate < 0.3:
                recommendations.append({
                    "type": name,
                    "issue": "low_success_rate",
                    "current_rate": metrics.success_rate,
                    "recommendation": "Lower temperature for more precise hypotheses"
                })
            
            # High false positive rate
            elif metrics.success_rate > 0.8 and metrics.avg_initial_confidence < 0.5:
                recommendations.append({
                    "type": name,
                    "issue": "low_initial_confidence",
                    "recommendation": "Increase creative temperature to explore more"
                })
            
            # Good performance - confidence improving
            elif metrics.success_rate > 0.6 and (metrics.avg_final_confidence - metrics.avg_initial_confidence) > 0.2:
                recommendations.append({
                    "type": name,
                    "issue": "good_performance",
                    "recommendation": "Current prompt strategy working well"
                })
        
        return {
            "recommendations": recommendations,
            "best_prompts": sorted(
                self.prompt_effectiveness.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
        
    def suggest_improvements(self) -> List[str]:
        """Suggest improvements based on learning data"""
        suggestions = []
        
        # Analyze pattern effectiveness
        low_confidence_patterns = [
            name for name, stats in self.pattern_effectiveness.items()
            if stats.confidence_score < 0.5 and stats.times_detected > 5
        ]
        
        if low_confidence_patterns:
            suggestions.append(
                f"Consider tuning these patterns with high false positive rates: {', '.join(low_confidence_patterns[:3])}"
            )
            
        # Check accuracy trend
        if len(self.accuracy_history) >= 20:
            recent = sum(self.accuracy_history[-10:]) / 10
            older = sum(self.accuracy_history[-20:-10]) / 10
            
            if recent < older:
                suggestions.append(
                    "Detection accuracy has decreased recently. Consider reviewing recent pattern changes."
                )
            elif recent > older:
                suggestions.append(
                    f"Detection accuracy improving! Recent: {recent:.2%}, Previous: {older:.2%}"
                )
                
        # Check coverage
        if len(self.vulnerability_corpus) < 10:
            suggestions.append(
                f"Limited vulnerability corpus ({len(self.vulnerability_corpus)} types). Run more diverse analyses."
            )
            
        return suggestions


    def update_adaptive_learning_data(self, adaptive_state: Dict[str, Any]):
        """
        Update adaptive learning fields from AdaptiveLearningSystem
        NEW: Support for adaptive learning integration
        """
        if 'prompt_performance' in adaptive_state:
            self.prompt_performance = adaptive_state['prompt_performance']
        
        if 'verification_weights' in adaptive_state:
            self.verification_weights = adaptive_state['verification_weights']
        
        if 'user_feedback_log' in adaptive_state:
            self.user_feedback_log = adaptive_state['user_feedback_log']
        
        # Initialize hypothesis quality trends if not exists
        if not hasattr(self, 'hypothesis_quality_trends') or not self.hypothesis_quality_trends:
            self.hypothesis_quality_trends = {
                'avg_confidence_over_time': [],
                'false_positive_rate_over_time': []
            }
        
        # Calculate current metrics
        if self.hypothesis_metrics:
            total_hypotheses = sum(m.total_generated for m in self.hypothesis_metrics.values())
            total_verified = sum(m.verified_count for m in self.hypothesis_metrics.values())
            
            if total_hypotheses > 0:
                avg_confidence = sum(
                    m.avg_final_confidence * m.total_generated 
                    for m in self.hypothesis_metrics.values()
                ) / total_hypotheses
                
                fp_rate = 1 - (total_verified / total_hypotheses)
                
                self.hypothesis_quality_trends['avg_confidence_over_time'].append(avg_confidence)
                self.hypothesis_quality_trends['false_positive_rate_over_time'].append(fp_rate)
        
        # Save to disk
        self.save_database()
    
    def get_adaptive_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive adaptive learning metrics
        NEW: Returns all adaptive learning data
        """
        return {
            'prompt_performance': self.prompt_performance,
            'verification_weights': self.verification_weights,
            'hypothesis_quality_trends': getattr(self, 'hypothesis_quality_trends', {}),
            'user_feedback': {
                'total_feedback': len(self.user_feedback_log),
                'recent_feedback': self.user_feedback_log[-10:] if self.user_feedback_log else []
            }
        }


# Global learning database instance
_global_learning_db = None


def get_learning_db() -> PersistentLearningDB:
    """Get or create the global learning database"""
    global _global_learning_db
    if _global_learning_db is None:
        _global_learning_db = PersistentLearningDB()
    return _global_learning_db


if __name__ == "__main__":
    # Demo the learning system
    print("="*70)
    print("PERSISTENT LEARNING SYSTEM - Demo")
    print("="*70)
    
    db = PersistentLearningDB("demo_learning.json")
    
    # Simulate some analyses
    for i in range(3):
        contract = f"contract Test{i} {{ function vulnerable() {{ }} }}"
        
        vulns = [
            {'name': 'reentrancy', 'severity': 'high'},
            {'name': 'overflow', 'severity': 'medium'}
        ]
        
        record = db.record_analysis(
            contract_code=contract,
            vulnerabilities_found=vulns,
            llm_insights=[f"Analysis {i} insight"],
            processing_time=1.5,
            user_feedback={'confirmed': 2, 'false_positives': []} if i > 0 else None
        )
        
        print(f"\n✓ Recorded analysis: {record.id}")
        
    # Show improvement
    metrics = db.get_improvement_metrics()
    print(f"\n📊 Improvement Metrics:")
    print(f"   Total scans: {metrics['total_scans']}")
    print(f"   Patterns learned: {metrics['total_patterns_learned']}")
    print(f"   Top pattern: {metrics['top_patterns'][0]['name']}")
    
    # Show enhanced prompt
    print(f"\n📝 Enhanced LLM Prompt (first 500 chars):")
    print(db.get_enhanced_llm_prompt()[:500])
    
    print("\n" + "="*70)
    print("✅ Learning system demonstrated!")
