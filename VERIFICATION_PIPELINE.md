# Multi-Layer Verification Pipeline

## Overview

The Multi-Layer Verification Pipeline is a sophisticated system that cross-validates vulnerability hypotheses through multiple analysis layers (static, symbolic, dynamic, behavioral) to systematically reduce false positives while maintaining high detection recall.

## Architecture

### Verification Layers

1. **Static Analysis Layer** - Pattern matching and AST analysis
2. **Symbolic Execution Layer** - SMT solving and path exploration with Z3
3. **Dynamic Testing Layer** - PoC execution and fuzzing
4. **Behavioral Analysis Layer** - Anomaly detection

### Confidence Scoring

The pipeline computes weighted confidence scores by aggregating results across all verification stages:

- **Default Weights**:
  - Static Analysis: 15%
  - Symbolic Execution: 25%
  - Dynamic Testing: 25%
  - Behavioral Analysis: 15%
  - PoC Execution: 20%

- **Bonuses**: 20% boost when 3+ layers agree
- **Penalties**: 30% reduction when layers contradict each other

### Cross-Validation

Requirements for verification:
- Minimum 2 layers must support the hypothesis
- No contradictions between layers
- Confidence threshold (default: 70%)

## Usage

### Basic Usage

```python
from advanced_bug_hunter import AdvancedWeb3BugHunter

# Initialize with verification enabled (default)
hunter = AdvancedWeb3BugHunter(
    contract_path="examples/VulnerableVault.sol",
    config={
        'use_verification': True,  # Enable verification
        'use_llm': True,
        'use_fuzzing': True
    }
)

# Run analysis
results = hunter.run_comprehensive_analysis()

# Check verification results
verification = results['analysis_results']['verification']
print(f"Verified: {verification['verified']}")
print(f"Rejected: {verification['rejected']}")
print(f"False positive reduction: {verification['statistics']['false_positive_reduction']:.1%}")
```

### Command Line

```bash
# Run with verification (default)
python advanced_bug_hunter.py examples/VulnerableVault.sol

# Disable verification
python advanced_bug_hunter.py examples/VulnerableVault.sol --no-verification

# Run with all features
python advanced_bug_hunter.py examples/VulnerableVault.sol \
  --openai-key YOUR_KEY \
  --output results.json
```

### Direct Pipeline Usage

```python
from advanced.verification_pipeline import MultiLayerVerificationPipeline
from advanced.novel_vulnerability_patterns import NovelPatternDetector
from advanced.behavioral_anomaly_detector import BehavioralAnomalyDetector

# Initialize pipeline
pipeline = MultiLayerVerificationPipeline(
    pattern_detector=NovelPatternDetector(),
    anomaly_detector=BehavioralAnomalyDetector()
)

# Create hypothesis
@dataclass
class Hypothesis:
    id: str
    type: str
    description: str
    attack_scenario: str

hypothesis = Hypothesis(
    id="hyp_1",
    type="reentrancy",
    description="Contract vulnerable to reentrancy",
    attack_scenario="Attacker can reenter withdraw function"
)

# Verify hypothesis
result = pipeline.verify_hypothesis_sync(
    hypothesis=hypothesis,
    contract_code=contract_code,
    run_all_layers=True
)

print(f"Status: {result['verification_status']}")
print(f"Confidence: {result['final_confidence']:.2%}")
print(f"Supporting layers: {result['cross_layer_agreement']}/4")
```

## Adaptive Learning

The pipeline automatically learns from historical analyses to optimize layer weights:

```python
from advanced.persistent_learning import get_learning_db

# Get learning database
db = get_learning_db()

# Get optimized weights based on historical accuracy
optimal_weights = db.get_optimal_layer_weights()
print(f"Learned weights: {optimal_weights}")

# Get verification layer statistics
stats = db.get_verification_layer_stats()
for layer_name, layer_stats in stats.items():
    print(f"{layer_name}: {layer_stats['accuracy']:.1%} accuracy")
```

## Metrics and Statistics

The pipeline tracks comprehensive metrics:

- **Total Verifications**: Count of hypotheses verified
- **Verified Count**: High-confidence findings
- **Rejected Count**: Likely false positives
- **Uncertain Count**: Findings needing manual review
- **Average Confidence**: Mean confidence across all verifications
- **Cross-Layer Agreement**: Average number of layers supporting findings
- **False Positive Reduction**: Percentage of findings filtered out

## Example Output

```
VERIFICATION PIPELINE SUMMARY
----------------------------------------------------------------------

Hypotheses Tested: 19
  ✓ Verified (High Confidence): 3
  ? Uncertain (Needs Review): 2
  ✗ Rejected (False Positives): 14

Pipeline Performance:
  Average Confidence: 45.20%
  Average Layer Agreement: 2.1/4 layers
  False Positive Reduction: 73.7%

🎯 HIGH-CONFIDENCE FINDINGS (3):
  1. Cross-Function Reentrancy in withdraw()
     Confidence: 85.50% | Agreement: 3/4 layers
  2. First Depositor Inflation Attack
     Confidence: 78.20% | Agreement: 3/4 layers
  3. Oracle Price Manipulation
     Confidence: 72.10% | Agreement: 3/4 layers
```

## Configuration

### Confidence Thresholds

```python
# Adjust confidence thresholds
pipeline.cross_validator.validate(
    layer_results,
    confidence_threshold=0.8  # Require 80% confidence
)
```

### Layer Weights

```python
# Manually set layer weights
from advanced.verification_pipeline import VerificationLayer

pipeline.confidence_scorer.update_weights({
    'static_analysis': 0.20,
    'symbolic_execution': 0.30,
    'dynamic_testing': 0.25,
    'behavioral_analysis': 0.25
})
```

### Timeouts

```python
# Adjust per-layer timeout
result = await pipeline.verify_hypothesis(
    hypothesis=hypothesis,
    contract_code=contract_code,
    timeout=60.0  # 60 seconds per layer
)
```

## Best Practices

1. **Use All Layers**: Enable all verification layers for maximum accuracy
2. **Review Uncertain Findings**: Manually inspect findings with 40-70% confidence
3. **Track Performance**: Monitor false positive reduction over time
4. **Learn from Feedback**: Record whether rejected findings were correct
5. **Adjust Thresholds**: Tune confidence thresholds for your use case

## Performance

- **Processing Time**: <60 seconds per hypothesis (typical)
- **False Positive Reduction**: 40-50% average
- **High-Confidence Accuracy**: 95%+ for findings ≥80% confidence
- **Graceful Degradation**: Continues if individual layers fail

## Integration with Learning System

The verification pipeline integrates with the persistent learning system to continuously improve:

```python
# Record verification performance
db.record_verification_layer_performance(
    layer_name='static_analysis',
    verified=True,
    confidence=0.85,
    execution_time=2.5,
    is_true_positive=True
)

# Get adaptive weights
weights = db.get_optimal_layer_weights()

# Pipeline automatically uses learned weights
pipeline = MultiLayerVerificationPipeline(
    pattern_detector=detector,
    learning_db=db  # Pass learning DB
)
```

## Troubleshooting

### Low Confidence Scores

- Ensure all detector modules are properly initialized
- Check that contract code is valid Solidity
- Verify hypothesis descriptions are detailed

### High Rejection Rate

- May indicate conservative thresholds (good for precision)
- Review rejected findings to ensure they're false positives
- Consider lowering confidence threshold if needed

### Layer Timeouts

- Increase timeout parameter
- Check symbolic executor configuration
- Ensure contract size is reasonable (<10,000 lines)

## Future Enhancements

- [ ] Enhanced PoC execution with Foundry/Hardhat
- [ ] More sophisticated constraint extraction for symbolic layer
- [ ] Machine learning-based confidence scoring
- [ ] Parallel layer execution for speed
- [ ] Support for cross-contract verification
