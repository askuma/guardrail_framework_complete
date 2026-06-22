#!/bin/bash
set -e

# Install premium GuardrailsAI hub validators when GUARDRAILS_TOKEN is provided.
#
# Free validators (DetectPII, SecretsPresent) are pre-baked into the image at
# build time and need no token.  Premium validators (ToxicLanguage) require an
# account token and are installed here at container start so the token is never
# baked into the image layer.
#
# Validators are written to ~/.guardrails/ which lives in the guardrail user's
# home directory.  They persist for the container's lifetime; recreating the
# container triggers a fresh install.

if [ -n "${GUARDRAILS_TOKEN}" ]; then
    echo "[guardrails] Token detected — configuring account..."

    # Try the configure command; show any errors so failures are diagnosable.
    # --enable-metrics is optional; if the installed version doesn't support it
    # we fall back to configure without that flag.
    if guardrails configure --token="${GUARDRAILS_TOKEN}" --enable-metrics false 2>&1; then
        echo "[guardrails] Account configured"
    elif guardrails configure --token="${GUARDRAILS_TOKEN}" 2>&1; then
        echo "[guardrails] Account configured (metrics flag not supported in this version)"
    else
        echo "[guardrails] WARN: configure failed — hub install may still work if token is cached"
    fi

    echo "[guardrails] Installing ToxicLanguage validator (LLM01 coverage)..."
    if guardrails hub install hub://guardrails/toxic_language 2>&1; then
        echo "[guardrails] ToxicLanguage installed successfully"
    else
        echo "[guardrails] WARN: ToxicLanguage install failed — LLM01 will use regex scorer"
        echo "[guardrails]   Verify token at https://hub.guardrailsai.com and rebuild the container"
    fi
else
    echo "[guardrails] No GUARDRAILS_TOKEN set — running with free validators only (DetectPII, SecretsPresent)"
fi

# NeMo Guardrails auto-detects the best available LLM provider for
# intent classification (first match wins):
#   OPENAI_API_KEY                                → OpenAI  gpt-3.5-turbo
#   AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT  → Azure   gpt-4o-mini
#   OLLAMA_BASE_URL                               → Ollama  llama3 (local, no key)
#   ANTHROPIC_API_KEY                             → Anthropic claude-haiku (needs LangChain)
# Without any key, NeMo uses colang pattern-matching only.
if   [ -n "${OPENAI_API_KEY}" ];        then echo "[nemo] provider: openai"
elif [ -n "${OPENROUTER_API_KEY}" ];   then echo "[nemo] provider: openrouter (model: ${OPENROUTER_MODEL:-meta-llama/llama-3.1-8b-instruct:free})"
elif [ -n "${AZURE_OPENAI_API_KEY}" ]; then echo "[nemo] provider: azure"
elif [ -n "${OLLAMA_BASE_URL}" ];      then echo "[nemo] provider: ollama (local)"
elif [ -n "${ANTHROPIC_API_KEY}" ];    then echo "[nemo] provider: anthropic (needs langchain)"
else                                        echo "[nemo] no LLM key — colang pattern-matching only"
fi

exec "$@"
