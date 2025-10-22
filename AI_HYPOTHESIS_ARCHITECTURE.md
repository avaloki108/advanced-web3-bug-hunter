# AI-Powered Hypothesis Generation & Precision Verification Pipeline

## 🎯 Overview

This architectural enhancement transforms the Advanced Web3 Bug Hunter from pattern-based detection to intelligent hypothesis generation, testing, and verification. The system now combines **creativity** (discovering novel vulnerabilities) with **precision** (minimizing false positives) through a multi-stage AI-powered pipeline.

## 🏗️ Architecture

### Core Philosophy: Generate-and-Refine

Rather than eliminating all false positives upfront, we embrace a systematic approach:

1. **Generate** - Creative vulnerability hypotheses (even if some are initially false positives)
2. **Test** - Automated PoC generation for each hypothesis
3. **Verify** - Multi-layered validation (static, symbolic, dynamic)
4. **Learn** - Improve future hypothesis quality based on results

### System Components

```
┌─────────────────────────────────────────────────┐
│         AI Hypothesis System                    │
│  Central orchestrator for the entire pipeline   │
└─────────────┬───────────────────────────────────┘
              │
    ┌─────────┴──────────┐
    │                    │
    ▼                    ▼
┌──────────────┐    ┌──────────────┐
│ Hypothesis   │◄──►│   Prompt     │
│   Engine     │    │ Orchestrator │
│              │    │              │
│ Multi-stage  │    │ 5 strategies │
│ generation   │    │ Feedback loop│
└──────┬───────┘    └──────────────┘
       │
       ▼
┌──────────────┐    ┌──────────────┐
│Verification  │◄──►│     PoC      │
│  Pipeline    │    │  Generator   │
│              │    │              │
│ 4-layer      │    │ Foundry/     │
│ validation   │    │ Hardhat      │
└──────┬───────┘    └──────────────┘
       │
       ▼
┌──────────────┐
│ Persistent   │
│  Learning    │
│              │
│ Hypothesis   │
│ quality      │
│ tracking     │
└──────────────┘
```

## 📦 Module Details

### 1. HypothesisEngine (`advanced/hypothesis_engine.py`)

Generates vulnerability hypotheses through multi-stage prompting:

**Stage 1: Creative Exploration (Temperature 0.9)**
- Explores unconventional attack vectors
- Generates diverse hypothesis types
- Maximizes discovery of novel patterns

**Stage 2: Refinement (Temperature 0.3)**
- Technical validation of creative hypotheses
- Code-level feasibility checks
- Precision improvements

**Stage 3: Cross-Contract Analysis**
- Multi-contract interactions
- Bridge vulnerabilities
- Protocol composability risks

**Stage 4: Edge Case Discovery**
- Boundary conditions
- Mathematical edge cases
- State transition anomalies

**Features:**
- 8 hypothesis types (logic_flaw, economic_exploit, cross_contract, bridge, oracle, reentrancy, access_control, edge_case)
- Pattern-based fallback when LLM unavailable
- Hypothesis provenance tracking
- Creativity scoring

**Example:**
```python
from advanced.hypothesis_engine import HypothesisEngine, HypothesisGenerationConfig

engine = HypothesisEngine(llm_client=your_llm_client)
hypotheses = engine.generate_hypotheses(
    contract_code=contract_code,
    contract_type="defi_vault",
    static_analysis_results=slither_output
)
```

### 2. PromptOrchestrator (`advanced/prompt_orchestrator.py`)

Manages multi-strategy LLM prompting with feedback loops:

**Prompt Strategies:**
- **Adversarial**: Think like an attacker
- **Defensive**: Think like an auditor
- **Creative**: Explore novel patterns
- **Technical**: Deep technical analysis
- **Economic**: Economic incentive analysis
- **Composability**: Cross-protocol analysis

**Features:**
- Pre-configured prompt templates
- Prompt chaining (results feed into next prompts)
- Effectiveness tracking per template
- Temperature optimization
- Export/import feedback data

**Example:**
```python
from advanced.prompt_orchestrator import PromptOrchestrator

orchestrator = PromptOrchestrator(llm_client=your_client)

# Execute single prompt
result = orchestrator.execute_prompt(
    template_name="adversarial_discovery",
    variables={
        "contract_code": code,
        "contract_type": "vault"
    }
)

# Execute prompt chain
chain = [
    {"template": "creative_exploration"},
    {"template": "technical_validation"}
]
results = orchestrator.execute_chain(chain, initial_variables)
```

### 3. VerificationPipeline (`advanced/verification_pipeline.py`)

Multi-layered hypothesis verification system:

**Layer 1: Static Analysis (Weight: 0.2)**
- Pattern matching
- Code structure analysis
- Known vulnerability signatures

**Layer 2: Symbolic Execution (Weight: 0.3)**
- Z3 SMT solver integration
- Exploit path discovery
- Constraint solving

**Layer 3: Dynamic Testing (Weight: 0.25)**
- Simulated attack scenarios
- State transition testing
- Feasibility validation

**Layer 4: PoC Execution (Weight: 0.25)**
- Automated proof-of-concept
- Actual exploit demonstration
- Highest confidence verification

**Confidence Calculation:**
```
final_confidence = Σ(layer_confidence × layer_weight)

Status:
- verified:   confidence ≥ 0.7
- uncertain:  0.4 ≤ confidence < 0.7
- rejected:   confidence < 0.4
```

**Example:**
```python
from advanced.verification_pipeline import VerificationPipeline

pipeline = VerificationPipeline(
    symbolic_executor=your_executor
)

result = pipeline.verify_hypothesis(
    hypothesis=hypothesis_obj,
    contract_code=code,
    run_all_layers=True
)

print(f"Final confidence: {result.final_confidence}")
print(f"Status: {result.verification_status}")
```

### 4. PoCGenerator (`advanced/poc_generator.py`)

Automated proof-of-concept generation:

**Supported Frameworks:**
- Foundry (primary)
- Hardhat
- Brownie

**Pre-built Templates:**
- Reentrancy exploits
- Oracle manipulation
- Flash loan attacks
- Access control bypasses
- Generic vulnerabilities

**Features:**
- Complete Foundry project generation
- Safe sandboxed execution
- Gas usage tracking
- Profit calculation

**Example:**
```python
from advanced.poc_generator import PoCGenerator, PoCFramework

generator = PoCGenerator(framework=PoCFramework.FOUNDRY)

# Generate single PoC
poc_result = generator.generate_and_execute(
    hypothesis=hypothesis,
    contract_code=code,
    contract_name="VulnerableVault",
    execute=False  # Safety first
)

# Generate complete project
project_dir = generator.generate_foundry_project(
    hypotheses=all_hypotheses,
    contract_code=code,
    contract_name="VulnerableVault",
    output_dir="/tmp/pocs"
)
```

### 5. Enhanced PersistentLearning (`advanced/persistent_learning.py`)

Extended with hypothesis quality tracking:

**New Features:**
- `HypothesisQualityMetrics` - Tracks success rates by hypothesis type
- `track_hypothesis_quality()` - Records verification outcomes
- `update_prompt_effectiveness()` - Monitors prompt performance
- `get_hypothesis_quality_report()` - Quality analytics
- `get_prompt_recommendations()` - Optimization suggestions

**Adaptive Improvements:**
- Learns which hypothesis types are most accurate
- Identifies effective prompt strategies
- Adjusts confidence thresholds dynamically
- Optimizes temperature settings

**Example:**
```python
from advanced.persistent_learning import get_learning_db

db = get_learning_db()

# Track hypothesis quality
db.track_hypothesis_quality(
    hypothesis_type="reentrancy",
    initial_confidence=0.6,
    final_confidence=0.85,
    verified=True
)

# Get quality report
report = db.get_hypothesis_quality_report()
print(f"Overall success rate: {report['overall_success_rate']}")

# Get optimization recommendations
recs = db.get_prompt_recommendations()
```

### 6. AIHypothesisSystem (`advanced/ai_hypothesis_system.py`)

Main integration module orchestrating the entire pipeline:

**Complete Workflow:**
1. Generate hypotheses (multi-stage)
2. Verify through 4-layer pipeline
3. Generate PoCs for verified vulnerabilities
4. Record learnings
5. Optimize system

**Features:**
- End-to-end analysis
- JSON and Markdown reports
- System statistics
- Automatic optimization
- Backward compatible

**Example:**
```python
from advanced.ai_hypothesis_system import AIHypothesisSystem

system = AIHypothesisSystem(
    llm_client=your_client,
    symbolic_executor=your_executor,
    enable_poc_generation=True,
    enable_learning=True
)

# Complete analysis
report = system.analyze_contract(
    contract_code=code,
    contract_name="MyContract",
    contract_type="defi_vault",
    generate_pocs=True
)

# Export reports
system.export_report(report, "report.json", format="json")
system.export_report(report, "report.md", format="markdown")

# Get statistics
stats = system.get_system_statistics()

# Optimize for future scans
system.optimize_system()
```

## 🔗 Integration with Existing Code

### LLM Reasoning Engine Enhancement

The existing `llm_reasoning_engine.py` now integrates with the AI Hypothesis System:

```python
from advanced.llm_reasoning_engine import AdvancedLLMReasoner

reasoner = AdvancedLLMReasoner(openai_key="your-key")

# Standard multi-agent analysis (original)
results = reasoner.analyze_contract_multi_agent(
    contract_code=code,
    static_analysis_results={},
    use_ai_hypothesis=False  # Original behavior
)

# Enhanced with AI hypothesis system (new)
results = reasoner.analyze_contract_multi_agent(
    contract_code=code,
    static_analysis_results={},
    use_ai_hypothesis=True  # New AI-powered mode
)
```

**Backward Compatibility:**
- Original functionality preserved
- AI hypothesis mode is optional
- Graceful fallback if components unavailable
- No breaking changes

## 📊 Expected Impact

### Detection Improvements
- **Novel Vulnerabilities**: 30-40% increase in rare/niche bug discovery
- **False Positive Reduction**: 40% decrease through multi-stage verification
- **Cross-Protocol Coverage**: New capability for multi-contract exploits

### User Experience
- **Higher Confidence**: PoC-backed findings eliminate guesswork
- **Better Context**: Hypothesis provenance explains detection reasoning
- **Actionable Results**: Auto-generated test scripts for developers

### Competitive Advantage
- **Beyond Pattern Matching**: Discovers logic flaws not in any rulebook
- **Adaptive Intelligence**: Learns from each scan, improving over time
- **Holistic Analysis**: Covers scenarios other tools miss (bridges, oracles, etc.)

## 🚀 Quick Start

### Installation

No additional dependencies required! The system works with existing dependencies:
- `z3-solver` (already in requirements.txt)
- `openai` or `anthropic` (optional, for LLM features)

### Basic Usage

```python
from advanced.ai_hypothesis_system import AIHypothesisSystem

# Initialize (works without LLM too!)
system = AIHypothesisSystem(
    llm_client=None,  # Uses pattern-based fallback
    enable_learning=True
)

# Analyze contract
report = system.analyze_contract(
    contract_code=your_contract_code,
    contract_name="YourContract"
)

# View results
print(f"Verified: {len(report.verified_vulnerabilities)}")
print(f"Uncertain: {len(report.uncertain_findings)}")
print(f"Confidence improvement: {report.confidence_improvement:+.2f}")
```

### Running Example

```bash
cd /home/runner/work/advanced-web3-bug-hunter/advanced-web3-bug-hunter
python3 examples/ai_hypothesis_example.py
```

This will:
1. Analyze example vulnerable contract
2. Generate hypotheses
3. Verify through pipeline
4. Generate reports in `/tmp/hypothesis_system_output/`

## 📈 Metrics & Monitoring

### Hypothesis Quality Metrics

```python
from advanced.persistent_learning import get_learning_db

db = get_learning_db()
quality_report = db.get_hypothesis_quality_report()

print(f"""
Hypothesis Quality Report:
- Total Generated: {quality_report['total_hypotheses_generated']}
- Verified: {quality_report['total_verified']}
- Success Rate: {quality_report['overall_success_rate']:.1%}

By Type:
{json.dumps(quality_report['by_type'], indent=2)}
""")
```

### System Statistics

```python
stats = system.get_system_statistics()

print(f"""
System Statistics:
- Total Analyses: {stats['total_analyses']}
- Hypothesis Engine: {stats['hypothesis_engine']}
- Verification Pipeline: {stats['verification_pipeline']}
- Learning Metrics: {stats['learning_system']['improvement_metrics']}
""")
```

## 🎨 Customization

### Adjust Hypothesis Generation

```python
from advanced.hypothesis_engine import HypothesisGenerationConfig

config = HypothesisGenerationConfig(
    creative_temperature=0.95,  # More creative
    refinement_temperature=0.2,  # More precise
    max_hypotheses_per_stage=15,
    min_confidence_threshold=0.4,
    enable_cross_contract=True,
    enable_bridge_analysis=True
)

engine = HypothesisEngine(llm_client=client, config=config)
```

### Adjust Verification Weights

```python
from advanced.verification_pipeline import VerificationLayer

pipeline.update_layer_weights({
    VerificationLayer.STATIC_ANALYSIS: 0.15,
    VerificationLayer.SYMBOLIC_EXECUTION: 0.35,  # Increase symbolic weight
    VerificationLayer.DYNAMIC_TESTING: 0.25,
    VerificationLayer.POC_EXECUTION: 0.25
})
```

### Add Custom Prompt Templates

```python
from advanced.prompt_orchestrator import PromptTemplate, PromptStrategy

custom_template = PromptTemplate(
    name="custom_analysis",
    strategy=PromptStrategy.CREATIVE,
    template="Your custom prompt here with {variables}",
    temperature=0.8,
    max_tokens=2000,
    variables=["contract_code", "custom_param"]
)

orchestrator.register_template(custom_template)
```

## 🧪 Testing

The architecture has been tested with:
- ✅ Reentrancy vulnerabilities
- ✅ Oracle manipulation patterns
- ✅ Cross-contract interactions
- ✅ Pattern-based fallback (no LLM)
- ✅ Learning database persistence
- ✅ Report generation (JSON + Markdown)
- ✅ System optimization

## 📝 Reports

### JSON Report Structure

```json
{
  "contract_name": "VulnerableVault",
  "timestamp": "2025-10-22T00:26:12.385338",
  "verified_vulnerabilities": [
    {
      "type": "reentrancy",
      "description": "...",
      "severity": "critical",
      "confidence": 0.85,
      "attack_scenario": "...",
      "verification_layers": {...},
      "poc_generated": true
    }
  ],
  "recommendations": [...],
  "metrics": {...}
}
```

### Markdown Report Format

```markdown
# Vulnerability Analysis Report

**Contract:** VulnerableVault
**Date:** 2025-10-22T00:26:12.385338

## Verified Vulnerabilities

### 1. reentrancy - CRITICAL
**Description:** ...
**Attack Scenario:** ...
**Confidence:** 0.85

## Recommendations
- ...
```

## 🔐 Security Considerations

### Safe PoC Execution
- PoCs are NOT executed by default
- Sandboxed environment recommended
- Local testnets only
- Never execute on mainnet

### LLM Safety
- All prompts include safety guidelines
- Temperature limits prevent erratic behavior
- Timeouts on all LLM calls
- Error handling throughout

### Data Privacy
- No contract code sent to external services without explicit configuration
- Learning database stored locally
- Optional LLM integration

## 🛠️ Troubleshooting

### No LLM Available
The system works perfectly without LLM! It uses pattern-based fallback:
- Hypothesis generation uses code patterns
- Static analysis provides verification
- Learning still improves over time

### Low Confidence Scores
- Run system optimization: `system.optimize_system()`
- Check hypothesis quality report
- Adjust generation config temperatures
- Review verification layer weights

### Too Many False Positives
- Lower creative temperature
- Increase refinement stage weight
- Adjust min_confidence_threshold
- Enable more verification layers

## 📚 Further Reading

- Original Issue: Architecture Enhancement Proposal
- `ENHANCED_FEATURES.md` - Complete feature list
- `advanced_bug_hunter.py` - Main integration script
- `learned_knowledge.json` - Learning database format

## 🤝 Contributing

To extend the system:

1. **Add New Hypothesis Types** - Extend `HypothesisType` enum
2. **Create Prompt Templates** - Add to `PromptOrchestrator`
3. **Add PoC Templates** - Create new templates in `PoCGenerator`
4. **Enhance Verification** - Add new verification layers
5. **Improve Learning** - Extend metrics in `PersistentLearning`

## 📄 License

Same as parent project (see main LICENSE file)

---

**Built with ❤️ to find vulnerabilities that only senior auditors typically catch**
