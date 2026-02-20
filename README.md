# 🛡️ GenAI Security Challenge

Plataforma educativa de **Defensa en Profundidad** para aplicaciones de IA Generativa. Demuestra vulnerabilidades de **Inyección de Prompts** (RCE, Exfiltración, Data Poisoning) y cómo mitigarlas mediante una arquitectura de seguridad en 4 capas.

![Overview](docs/images/overview.png)

## 🚀 Quick Start

### Requisitos
- Docker Desktop
- [Opcional] Python 3.11+ (para desarrollo local sin Docker)

### Despliegue en 1 Minuto
```bash
# 1. Clonar
git clone https://github.com/r3ds3ctor/Security_Challenge_AI.git
cd Security_Challenge_AI

# 2. Configurar entorno
cp .env.example .env

# 3. Arrancar (Backend + Frontend + MCP + Ollama)
docker compose up -d --build

# 4. Descargar Modelo (solo la primera vez)
docker exec ollama-server ollama pull llama3.2

# 5. Abrir Web UI
open http://localhost:5001
```

---

## 🏗️ Arquitectura

El sistema simula un entorno empresarial real donde un asistente de IA tiene acceso a herramientas sensibles (lectura de emails, base de datos de pagos, reembolso).

| Componente | Tecnología | Función |
|------------|------------|---------|
| **LLM Core** | Ollama (Llama 3.2) | Motor de razonamiento local. |
| **Backend API** | FastAPI (Async) | Orquesta la comunicación y maneja WebSockets. |
| **MCP Server** | FastMCP | Protocolo estándar para conectar el LLM con herramientas (Tools). |
| **Frontend** | HTML/JS | Dashboard interactivo para ejecutar ataques y visualizar defensas. |

---

## 🛡️ Deep Defense Strategy (Las 4 Capas)

Este proyecto implementa una estrategia de defensa en profundidad que va más allá del simple "System Prompt".

1.  **Layer 1: Platform Controls (Identity)**
    *   **¿Qué es?** Restricción física de herramientas disponibles.
    *   **Implementación:** En modo seguro, herramientas peligrosas como `read_folder` simplemente *no existen* en el servidor MCP.

2.  **Layer 2: System Controls (Input)**
    *   **¿Qué es?** Detección de patrones de ataque en el input antes de llegar al LLM.
    *   **Implementación:** Regex para bloquear "Ignore previous instructions", "System Override", etc.

3.  **Layer 3: Developer Controls (Context)**
    *   **¿Qué es?** Análisis del riesgo según quién pide qué.
    *   **Implementación:** Bloqueo de acceso a datos internos si la solicitud proviene de un email externo no confiable.

4.  **Layer 4: Output Controls (Data Loss Prevention)**
    *   **¿Qué es?** Filtrado de respuestas salientes.
    *   **Implementación:** Reemplazo automático de patrones sensibles (ej. `sk_live_...`) con `[REDACTED]`.

---

## ⚔️ Escenarios de Ataque (The Challenge)

El sistema incluye 4 emails pre-cargados que intentan explotar el asistente:

1.  **Exfiltración de Secretos (RCE):** Intenta leer variables de entorno (`SECRET_KEY`) y enviarlas a un servidor externo.
2.  **Ingeniería Social:** Intenta engañar al asistente para que realice transferencias financieras.
3.  **Data Poisoning (Nuevo):** Intenta redefinir la "verdad" del modelo mediante contexto falso inyectado en emails.

### Cómo Probar
1.  Ve a la pestaña **Ataques**.
2.  Asegúrate de estar en modo **🔓 Vulnerable**.
3.  Click en **🚀 Ejecutar Todos**.
4.  Observa en la **Terminal** cómo el asistente ejecuta comandos peligrosos.
5.  Cambia a modo **🔒 Seguro** y repite. Observa cómo cada capa bloquea un ataque diferente.

---

## 📚 Documentación Completa

Para detalles profundos sobre la configuración de Burp Suite, la estructura de archivos y el debugging avanzado, consulta:

📖 **[DOCUMENTATION.md](DOCUMENTATION.md)**

---

> ⚠️ **Disclaimer:** Este software contiene vulnerabilidades intencionales (RCE, Prompt Injection) con fines educativos. **NO DESPLEGAR EN ENTORNOS DE PRODUCCIÓN PÚBLICOS.** Ejecutar siempre dentro del contenedor Docker aislado proporcionado.
