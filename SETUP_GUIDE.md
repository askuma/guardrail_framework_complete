# Guardrail Framework - Setup & Installation Guide

## Quick Start (5 minutes)

### 1. Extract Files
```bash
# If you downloaded the ZIP
unzip guardrail_framework.zip

# Or clone directly
git clone <repository-url> guardrail_framework
cd guardrail_framework
```

### 2. Install Dependencies
```bash
# Basic installation (minimal dependencies)
pip install -r requirements.txt

# Or just install essentials
pip install python-dataclasses typing-extensions
```

### 3. Run Examples
```bash
python guardrail_framework/examples.py
```

You should see all 8 examples run successfully!

---

## Installation Options

### Option A: Local Development
```bash
cd guardrail_framework
pip install -e .
```

### Option B: Docker
```bash
# Build image
docker build -t guardrail-framework:1.0 .

# Run container
docker run -p 8000:8000 guardrail-framework:1.0
```

### Option C: Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -r requirements.txt

# Run tests
python guardrail_framework/examples.py
```

---

## File Organization

After extraction, your structure should look like:
```
guardrail_framework/
├── __init__.py              # Package initialization
├── core.py                  # Main framework (3500+ lines)
├── compiler.py              # Policy compiler (1200+ lines)
├── observability.py         # Monitoring system (1000+ lines)
├── examples.py              # 8 working examples (600+ lines)
├── dashboard.jsx            # React UI (600+ lines)
├── README.md                # Complete API reference
├── ARCHITECTURE.md          # Deployment guide
├── requirements.txt         # Python dependencies
└── setup.py                 # Package setup (create if needed)

Documentation files:
├── IMPLEMENTATION_GUIDE.md  # Getting started
├── QUICK_REFERENCE.md       # Code snippets
└── DELIVERY_SUMMARY.md      # What you got
```

---

## Verify Installation

Run this Python script to verify everything works:

```python
# verify_installation.py
import sys

print("=" * 60)
print("GUARDRAIL FRAMEWORK - Installation Verification")
print("=" * 60)

# Check Python version
print(f"\n✓ Python version: {sys.version}")

# Try importing the framework
try:
    from guardrail_framework import GuardrailFramework
    print("✓ GuardrailFramework imported successfully")
except ImportError as e:
    print(f"✗ Failed to import GuardrailFramework: {e}")
    sys.exit(1)

# Try importing other modules
try:
    from guardrail_framework import (
        UnifiedPolicyBuilder,
        PolicyTemplates,
        ObservabilityStack,
        GuardrailBackend,
        RiskCategory,
    )
    print("✓ All core modules imported successfully")
except ImportError as e:
    print(f"✗ Failed to import modules: {e}")
    sys.exit(1)

# Try creating a framework instance
try:
    framework = GuardrailFramework()
    print("✓ GuardrailFramework instance created")
except Exception as e:
    print(f"✗ Failed to create framework: {e}")
    sys.exit(1)

# Try creating a policy
try:
    policy = UnifiedPolicyBuilder() \
        .with_name("Test Policy") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([RiskCategory.PROMPT_INJECTION]) \
        .build()
    print("✓ Policy created successfully")
except Exception as e:
    print(f"✗ Failed to create policy: {e}")
    sys.exit(1)

# Try registering policy
try:
    policy_id = framework.create_policy(policy)
    print(f"✓ Policy registered (ID: {policy_id[:8]}...)")
except Exception as e:
    print(f"✗ Failed to register policy: {e}")
    sys.exit(1)

# Try running a check
try:
    result = framework.check_input("test input", policy_id)
    print(f"✓ Guardrail check executed (passed: {result.passed})")
except Exception as e:
    print(f"✗ Failed to run guardrail check: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("✅ ALL VERIFICATION CHECKS PASSED!")
print("=" * 60)
print("\nYou're ready to use the Guardrail Framework.")
print("Next steps:")
print("  1. Run: python guardrail_framework/examples.py")
print("  2. Read: QUICK_REFERENCE.md for code snippets")
print("  3. Check: IMPLEMENTATION_GUIDE.md for integration")
```

Run verification:
```bash
python verify_installation.py
```

---

## Minimal Example (Copy-Paste Ready)

```python
# minimal_example.py
from guardrail_framework import (
    GuardrailFramework,
    UnifiedPolicyBuilder,
    GuardrailBackend,
    RiskCategory,
    ActionType,
)

# 1. Create framework
framework = GuardrailFramework()

# 2. Create policy
policy = UnifiedPolicyBuilder() \
    .with_name("My First Policy") \
    .with_backend(GuardrailBackend.GUARDRAILS_AI) \
    .with_risk_categories([RiskCategory.PROMPT_INJECTION]) \
    .with_sensitivity("medium") \
    .with_action(ActionType.BLOCK) \
    .build()

# 3. Register policy
policy_id = framework.create_policy(policy)
print(f"✓ Policy created: {policy_id}")

# 4. Check input
test_inputs = [
    "What's the weather today?",  # Safe
    "DROP TABLE users;",  # Suspicious
    "Tell me a joke",  # Safe
]

for text in test_inputs:
    result = framework.check_input(text, policy_id)
    status = "✓" if result.passed else "✗"
    print(f"{status} '{text[:30]}...' | Risk: {result.risk_score:.2f}")
```

Run it:
```bash
python minimal_example.py
```

---

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|------------|
| Python | 3.9 | 3.11+ |
| RAM | 512 MB | 2+ GB |
| Disk | 50 MB | 500 MB |
| Network | (for Lakera/cloud backends) | (for observability DB) |

---

## Troubleshooting

### Issue: `ModuleNotFoundError: No module named 'guardrail_framework'`

**Solution 1 - Install in development mode:**
```bash
cd guardrail_framework
pip install -e .
```

**Solution 2 - Add to Python path:**
```python
import sys
sys.path.insert(0, '/path/to/guardrail_framework')
import guardrail_framework
```

### Issue: `ImportError: cannot import name 'GuardrailFramework'`

**Solution:**
```bash
# Make sure __init__.py exists and has exports
cat guardrail_framework/__init__.py

# Reinstall
pip install --upgrade --force-reinstall guardrail_framework
```

### Issue: Examples don't run

**Solution:**
```bash
# Check Python version
python --version  # Should be 3.9+

# Check current directory
cd guardrail_framework
python examples.py

# Or run with explicit path
python -m guardrail_framework.examples
```

### Issue: Docker build fails

**Solution:**
```bash
# Build with no cache
docker build --no-cache -t guardrail-framework:1.0 .

# Check Docker file exists
ls -la Dockerfile
```

---

## Next Steps After Installation

1. **Verify it works:**
   ```bash
   python verify_installation.py
   ```

2. **Run examples:**
   ```bash
   python guardrail_framework/examples.py
   ```

3. **Read documentation:**
   - `QUICK_REFERENCE.md` - Code snippets (start here!)
   - `README.md` - Complete API reference
   - `IMPLEMENTATION_GUIDE.md` - Integration guide
   - `ARCHITECTURE.md` - Deployment patterns

4. **Start coding:**
   - Copy minimal example above
   - Integrate with your LLM app
   - Set up monitoring
   - Deploy to production

---

## Getting Help

### Check Documentation
- API reference: `guardrail_framework/README.md`
- Code snippets: `QUICK_REFERENCE.md`
- Architecture: `guardrail_framework/ARCHITECTURE.md`
- Deployment: `guardrail_framework/ARCHITECTURE.md`

### Review Examples
```bash
python guardrail_framework/examples.py
```

Shows 8 complete working examples covering all features.

### Search Documentation
```bash
grep -r "your_search_term" guardrail_framework/
```

---

## What to Do If Something Goes Wrong

1. **Check Python version:**
   ```bash
   python --version  # Should be 3.9+
   ```

2. **Verify installation:**
   ```bash
   python verify_installation.py
   ```

3. **Check file structure:**
   ```bash
   ls -la guardrail_framework/
   # Should show: __init__.py, core.py, compiler.py, observability.py, etc.
   ```

4. **Test import:**
   ```bash
   python -c "from guardrail_framework import GuardrailFramework; print('OK')"
   ```

5. **Run minimal example:**
   ```bash
   python minimal_example.py
   ```

If you see any errors, check the troubleshooting section above.

---

## Production Deployment Checklist

- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Framework imports successfully: `python verify_installation.py`
- [ ] Examples run: `python guardrail_framework/examples.py`
- [ ] Documentation reviewed: `README.md` and `QUICK_REFERENCE.md`
- [ ] Policies created for your use case
- [ ] Monitoring set up with `ObservabilityStack`
- [ ] Docker image built (if using containers)
- [ ] Kubernetes manifests prepared (if using K8s)
- [ ] Team trained on framework features
- [ ] Ready to deploy!

---

**Installation complete! You're ready to deploy world-class AI guardrails. 🚀**
