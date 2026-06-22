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
    echo "[guardrails] Token detected — configuring and installing premium validators..."

    # Write config directly instead of using `guardrails configure` — the CLI
    # --enable-metrics flag syntax has changed across versions and is unreliable.
    mkdir -p "${HOME}/.guardrails"
    printf '[DEFAULT]\ntoken = %s\nenable_metrics = False\n' "${GUARDRAILS_TOKEN}" \
        > "${HOME}/.guardrails/config"

    # PIP_USER=1 directs pip to ~/.local (no root required for the guardrail user).
    PIP_USER=1 guardrails hub install hub://guardrails/toxic_language --quiet 2>/dev/null \
        && echo "[guardrails] ToxicLanguage installed (LLM01 coverage)" \
        || echo "[guardrails] WARN: ToxicLanguage install failed — LLM01 will use regex scorer"
else
    echo "[guardrails] No GUARDRAILS_TOKEN set — running with free validators only (DetectPII, SecretsPresent)"
fi

# NeMo Guardrails uses OPENAI_API_KEY for LLM-based intent classification.
# A default colang policy covering OWASP LLM01 patterns is built into the
# backend and requires no extra setup.  When OPENAI_API_KEY is set, NeMo
# classifies subtle injection variants the colang patterns might miss.
if [ -n "${OPENAI_API_KEY}" ]; then
    echo "[nemo] OPENAI_API_KEY detected — NeMo will use LLM-based intent classification"
else
    echo "[nemo] No OPENAI_API_KEY — NeMo will use colang pattern-matching only"
fi

exec "$@"
