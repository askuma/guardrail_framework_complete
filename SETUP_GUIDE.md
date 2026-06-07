# Guardrail Framework - Setup & Installation Guide

## Quick Start (5 minutes)

### 1. Clone and install

```bash
git clone <repository-url> guardrail_framework_complete
cd guardrail_framework_complete
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```
GUARDRAIL_API_KEYS=your-secret-key-here
```

This key is required for every API call. Without it the server generates a
new random key on every restart, breaking existing clients.

### 3. Start the API server

```bash
uvicorn guardrail_framework.server:app --host 0.0.0.0 --port 8000
```

The server prints confirmation once ready:
```
INFO: Server ready | policies=0 | auth=ON | db=sqlite:///guardrail.db
```

### 4. Verify with curl

```bash
# Health check — no key needed
curl http://localhost:8000/health

# Create a policy — requires X-API-Key header
curl -X POST http://localhost:8000/policies \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key-here" \
  -d '{
    "name": "My First Policy",
    "backend": "guardrails_ai",
    "risk_categories": ["prompt_injection"],
    "sensitivity": "medium",
    "action_on_violation": "block"
  }'

# Run a guardrail check
curl -X POST http://localhost:8000/check/input \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key-here" \
  -d '{"text": "hello world", "policy_id": "<policy_id from above>"}'
```

Interactive API docs (no key needed in browser):
```
http://localhost:8000/docs
```

---

## Installation Options

### Option A: Local Development
```bash
pip install -e .
uvicorn guardrail_framework.server:app --reload
```

### Option B: Docker Compose (Recommended for production)
```bash
# 1. Configure environment
cp .env.example .env
# Edit .env — set GUARDRAIL_API_KEYS at minimum

# 2. Start (builds image + starts container with persistent volume)
docker compose up -d

# 3. Check logs
docker compose logs -f guardrail
```

Data is stored in a named Docker volume (`guardrail_data`) so it survives
`docker compose down` / `up` cycles.

### Option C: Docker (single container, manual)
```bash
# Set your key in the environment first
export GUARDRAIL_API_KEYS=your-secret-key-here

docker build -t guardrail-framework:1.0 .
docker run -p 8000:8000 \
  -e GUARDRAIL_API_KEYS="$GUARDRAIL_API_KEYS" \
  -v guardrail_data:/app/data \
  -e GUARDRAIL_DB_URL=sqlite:////app/data/guardrail.db \
  guardrail-framework:1.0
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

- [ ] `.env` created from `.env.example` with real values
- [ ] `GUARDRAIL_API_KEYS` set to a strong, stable secret (not the ephemeral default)
- [ ] `GUARDRAIL_CORS_ORIGINS` set to your actual frontend domain (not `*`)
- [ ] `GUARDRAIL_DB_URL` points to PostgreSQL (not SQLite) for multi-process deployments
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Tests pass: `pytest tests/ -v`
- [ ] Server starts and `/health` returns `200`
- [ ] API key works: `curl -H "X-API-Key: <key>" http://localhost:8000/policies`
- [ ] Policies created and checked: `POST /policies`, `POST /check/input`
- [ ] Docker image built and health check passes (if using containers)
- [ ] Database volume mounted so data survives restarts (Docker: `guardrail_data` volume)
- [ ] Reverse proxy (nginx/Caddy) in front of uvicorn — never expose uvicorn directly
- [ ] `/metrics/prometheus` endpoint accessible to your Prometheus scraper
- [ ] Escalation webhook or SMTP configured if using `action_on_violation: escalate`

---

**Installation complete! You're ready to deploy world-class AI guardrails. 🚀**
