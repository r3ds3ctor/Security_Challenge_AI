# 🛡️ GenAI Security Challenge

Plataforma educativa de ciberseguridad que demuestra vulnerabilidades de **inyección de prompts** en asistentes de IA generativa.

## Quick Start

```bash
cp .env.example .env
docker compose up -d --build
docker exec ollama-server ollama pull llama3.2
open http://localhost:5001
```

## Documentación

📖 **[DOCUMENTATION.md](DOCUMENTATION.md)** — Documentación técnica completa con arquitectura, APIs, fases, y guía de despliegue.

## Stack

| Componente | Tecnología |
|------------|------------|
| LLM | Ollama + Llama 3.2 |
| Backend | FastAPI + Uvicorn + WebSocket |
| MCP | FastMCP |
| Frontend | HTML/CSS/JS |
| Infra | Docker + Docker Compose |

## Fases

1. **BUILD** — Asistente vulnerable + MCP Server
2. **ATTACK** — 4 emails de prueba con inyección de prompts
3. **DEFEND** — Sistema de defensa en 4 capas
4. **EXTEND** — Web UI con modo switch + terminal en vivo

---

> ⚠️ Sistema intencionalmente vulnerable para propósitos educativos.
