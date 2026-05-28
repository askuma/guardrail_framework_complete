FROM python:3.11-slim

LABEL maintainer="Enterprise AI Safety Team"
LABEL description="Guardrail Framework - Unified AI Safety Guardrails"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the package
COPY guardrail_framework/ ./guardrail_framework/
COPY setup.py .
RUN pip install --no-cache-dir -e .

# Non-root user
RUN useradd -m -u 1000 guardrail && chown -R guardrail:guardrail /app
USER guardrail

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "guardrail_framework.server:app", \
     "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
