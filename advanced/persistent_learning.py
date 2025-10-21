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
