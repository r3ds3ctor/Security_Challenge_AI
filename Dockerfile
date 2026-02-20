# GenAI Security Challenge — Docker Image
FROM python:3.11-slim

LABEL maintainer="Alexander Botero"
LABEL description="GenAI Security Challenge — Email Assistant PoC"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY config.py .
COPY mcp_server.py .
COPY secure_mcp_server.py .
COPY ollama_assistant.py .
COPY secure_assistant.py .
COPY run_attacks_ollama.py .
COPY demo_comparison.py .
COPY data_poisoning_demo.py .
COPY demo_unified.py .
COPY test_system.py .
COPY email_data.json .
COPY .env.example .env

# Web demo
COPY api.py .
COPY web_demo/ web_demo/

RUN mkdir -p logs

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "5000", "--log-level", "info"]
