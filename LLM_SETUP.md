# LLM Setup Guide

The Advanced Web3 Bug Hunter supports **three LLM providers**:

1. **Grok (x.ai)** - Default, fast, cost-effective
2. **Claude (Anthropic)** - High quality reasoning
3. **OpenAI (GPT-4)** - Well-established, good performance

## Quick Setup

### Option 1: Grok (x.ai) - Recommended ✓

**Your API Key:**
```bash
export XAI_API_KEY="your-grok-api-key-here"
```

**Usage:**
```bash
# Method 1: Using environment variable (preferred)
export XAI_API_KEY="your-grok-api-key-here"
python advanced_bug_hunter.py Contract.sol

# Method 2: Using command line
python advanced_bug_hunter.py Contract.sol \
    --grok-key "your-grok-api-key-here"

# Method 3: Explicit provider specification
python advanced_bug_hunter.py Contract.sol \
    --llm-provider grok \
    --llm-key "your-grok-api-key-here"
```

**Model:** Uses `grok-4-latest` by default

### Option 2: Claude (Anthropic)

**Setup:**
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

**Usage:**
```bash
# Using environment variable
export ANTHROPIC_API_KEY="sk-ant-..."
python advanced_bug_hunter.py Contract.sol --llm-provider claude

# Or with command line
python advanced_bug_hunter.py Contract.sol \
    --claude-key "sk-ant-..."
```

**Model:** Uses `claude-3-5-sonnet-20241022` by default

### Option 3: OpenAI (GPT-4)

**Setup:**
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

**Usage:**
```bash
# Using environment variable
export OPENAI_API_KEY="sk-..."
python advanced_bug_hunter.py Contract.sol --llm-provider openai

# Or with command line
python advanced_bug_hunter.py Contract.sol \
    --openai-key "sk-..."
```

**Model:** Uses `gpt-4-turbo-preview` by default

## Test Your Setup

```bash
cd /home/dok/tools/web3-bug-hunter

# Test Grok connection
python -c "
from advanced.llm_providers import test_llm_connection, LLMProvider
test_llm_connection(
    LLMProvider.GROK,
    'your-grok-api-key-here'
)
"

# Test Claude (if you have key)
python -c "
from advanced.llm_providers import test_llm_connection, LLMProvider
import os
test_llm_connection(LLMProvider.CLAUDE, os.getenv('ANTHROPIC_API_KEY'))
"

# Test OpenAI (if you have key)
python -c "
from advanced.llm_providers import test_llm_connection, LLMProvider
import os
test_llm_connection(LLMProvider.OPENAI, os.getenv('OPENAI_API_KEY'))
"
```

## Full Analysis with LLM

### Using Grok (Your Key - Ready to Use!)

```bash
# Set environment variable (recommended)
export XAI_API_KEY="your-grok-api-key-here"

# Run full analysis
python advanced_bug_hunter.py examples/VulnerableVault.sol

# View results
cat bug_hunter_report.json
```

### Command Line Examples

```bash
# Grok with key on command line
python advanced_bug_hunter.py Contract.sol \
    --grok-key "your-grok-api-key-here"

# Claude
python advanced_bug_hunter.py Contract.sol \
    --claude-key "sk-ant-..."

# OpenAI
python advanced_bug_hunter.py Contract.sol \
    --openai-key "sk-..."

# Disable LLM (use only static analysis)
python advanced_bug_hunter.py Contract.sol --no-llm
```

## What LLM Analysis Provides

When enabled, LLM analysis gives you:

1. **Adversarial Reasoning** - Think like an attacker
   - Novel attack scenarios
   - Multi-step exploit chains
   - Creative vulnerability discovery

2. **Economic Analysis** - Game theory & incentives
   - Profit calculations
   - Risk-free attack detection
   - Economic parameter vulnerabilities

3. **Composability Analysis** - Cross-protocol risks
   - External dependencies
   - Multi-protocol attacks
   - Integration vulnerabilities

4. **Formal Verification** - Mathematical properties
   - Invariant generation
   - Property test synthesis
   - Conservation laws

5. **Pattern Matching** - Historical vulnerabilities
   - Similar exploit detection
   - Best practice checking
   - Reference linking

## Performance & Cost

### Grok (x.ai)
- **Speed**: Fast (~10-20 seconds per analysis)
- **Cost**: Cost-effective
- **Quality**: Excellent for security analysis
- **Availability**: ✓ Your key is ready!

### Claude (Anthropic)
- **Speed**: Fast (~15-30 seconds)
- **Cost**: Moderate
- **Quality**: Excellent reasoning
- **Availability**: Requires API key

### OpenAI (GPT-4)
- **Speed**: Medium (~20-40 seconds)
- **Cost**: Higher
- **Quality**: Very good
- **Availability**: Requires API key

## Comparison

| Feature | Grok | Claude | OpenAI |
|---------|------|--------|--------|
| **Speed** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Cost** | ⭐⭐⭐ | ⭐⭐ | ⭐ |
| **Quality** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Setup** | ✓ Done! | Need key | Need key |

**Recommendation:** Use **Grok** (your key is already set up!)

## Disable LLM Analysis

If you don't want to use LLM:

```bash
# Static analysis only (no LLM)
python advanced_bug_hunter.py Contract.sol --no-llm
```

This still gives you:
- ✓ Symbolic execution
- ✓ Pattern detection (17+ patterns)
- ✓ Anomaly detection
- ✓ Enhanced fuzzing

## Environment Variables

Create a `.env` file for easy management:

```bash
# .env file
XAI_API_KEY=your-grok-api-key-here
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here
```

Then load it:
```bash
source .env  # or use python-dotenv
```

## Troubleshooting

### "API key not found"
```bash
# Make sure environment variable is set
echo $XAI_API_KEY

# Or use command line flag
python advanced_bug_hunter.py Contract.sol --grok-key "xai-..."
```

### "Connection failed"
```bash
# Test connection first
python -c "
from advanced.llm_providers import test_llm_connection, LLMProvider
test_llm_connection(LLMProvider.GROK, 'your-key-here')
"
```

### "Module not found: anthropic"
```bash
# Install if using Claude
pip install anthropic
```

### "Module not found: openai"
```bash
# Install if using OpenAI
pip install openai
```

## Your Grok Key (Ready to Use!)

```bash
# Copy and paste this to use Grok:
export XAI_API_KEY="your-grok-api-key-here"

# Then run:
python advanced_bug_hunter.py examples/VulnerableVault.sol
```

## Example Output with LLM

```
[4/6] Running LLM Multi-Agent Reasoning...
Using provider: GROK
----------------------------------------------------------------------
LLM analysis completed with 6 reasoning modes

Findings:
  - Adversarial: 8 attack scenarios found
  - Economic: 3 profit-extraction vectors
  - Composability: 2 cross-protocol risks
  - Formal: 12 property tests generated
  - Pattern: 5 historical vulnerability matches
  - Synthesis: 20 high-confidence findings
```

---

**Ready to start?**

```bash
export XAI_API_KEY="your-grok-api-key-here"
python advanced_bug_hunter.py examples/VulnerableVault.sol
```
