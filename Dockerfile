FROM python:3.11-slim

LABEL maintainer="Enterprise AI Safety Team"
LABEL description="Guardrail Framework - Unified AI Safety Guardrails"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy framework code
COPY guardrail_framework/ ./guardrail_framework/
COPY setup.py .

# Install the package
RUN pip install --no-cache-dir -e .

# Create non-root user for security
RUN useradd -m -u 1000 guardrail && chown -R guardrail:guardrail /app
USER guardrail

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports
EXPOSE 8000 8001

# Default command (FastAPI server)
CMD ["uvicorn", "guardrail_framework.server:app", "--host", "0.0.0.0", "--port", "8000"]
