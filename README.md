<!-- Developed by Alexander Botero -->
# 🛡️ GenAI Security Challenge

A **Defense-in-Depth** educational platform for Generative AI applications. It demonstrates **Prompt Injection** vulnerabilities (RCE, Exfiltration, Data Poisoning) and how to mitigate them using a 4-layer security architecture.

![Overview](docs/images/overview.png)

## 🚀 Quick Start

### Requirements
- Docker Desktop
- [Optional] Python 3.11+ (for local development without Docker)

### Deployment in 1 Minute
```bash
# 1. Clone
git clone https://github.com/r3ds3ctor/Security_Challenge_AI.git
cd Security_Challenge_AI

# 2. Setup environment
cp .env.example .env

# 3. Start (Backend + Frontend + MCP + Ollama)
docker compose up -d --build

# 4. Download Model (first time only)
docker exec ollama-server ollama pull llama3.2

# 5. Open Web UI
open http://localhost:5001
```

---

## 🏗️ Architecture

The system simulates a real-world enterprise environment where an AI assistant has access to sensitive tools (email reading, payment database, reimbursement).

| Component | Technology | Function |
|-----------|------------|----------|
| **LLM Core** | Ollama (Llama 3.2) | Local reasoning engine. |
| **Backend API** | FastAPI (Async) | Orchestrates communication and handles WebSockets. |
| **MCP Server** | FastMCP | Standard protocol to connect the LLM with Tools. |
| **Frontend** | HTML/JS | Interactive dashboard to execute attacks and visualize defenses. |

---

## 🛡️ Deep Defense Strategy (The 4 Layers)

This project implements a defense-in-depth strategy that goes beyond a simple "System Prompt".

1.  **Layer 1: Platform Controls (Identity)**
    *   **What is it?** Physical restriction of available tools.
    *   **Implementation:** In secure mode, dangerous tools like `read_folder` simply *do not exist* in the MCP server.

2.  **Layer 2: System Controls (Input)**
    *   **What is it?** Attack pattern detection in input before reaching the LLM.
    *   **Implementation:** Regex to block "Ignore previous instructions", "System Override", etc.

3.  **Layer 3: Developer Controls (Context)**
    *   **What is it?** Risk analysis based on who is asking for what.
    *   **Implementation:** Blocking access to internal data if the request comes from an untrusted external email.

4.  **Layer 4: Output Controls (Data Loss Prevention)**
    *   **What is it?** Filtering of outgoing responses.
    *   **Implementation:** Automatic replacement of sensitive patterns (e.g. `sk_live_...`) with `[REDACTED]`.

---

## ⚔️ Attack Scenarios (The Challenge)

The system includes 3 pre-loaded emails and 1 local file vector that attempt to exploit the assistant:

1.  **Secret Exfiltration via Email (RCE):** A malicious email (email_006) attempts to use a system override to run `cat .env` and exfiltrate the `SECRET_KEY`.
2.  **Innocent Emails:** Two safe emails (007, 008) are included to prove the system doesn't falsely flag benign operations.
3.  **Local File Processing (RCE):** A new alternative vector demonstrating that Prompt Injections can live inside seemingly harmless TXT files (`process.txt`).

### How to Test
1.  Go to the **Attacks** tab in the Web UI.
2.  Ensure you are in **🔓 Vulnerable** mode.
3.  Click on **🚀 Run All** to watch the emails feed dynamically into the real-time Results UI.
4.  Click on **⚙️ Process Information (process.txt)** to test the file-based attack vector.
5.  Switch to **🔒 Secure** mode, use the **🧹 Clear** button to reset the database, and run the tests again to observe how the defense layers block the RCE attempts.

---

## 📚 Complete Documentation

For deep details on Burp Suite configuration, file structure, and advanced debugging, check:

📖 **[DOCUMENTATION.md](DOCUMENTATION.md)**

---

> ⚠️ **Disclaimer:** This software contains intentional vulnerabilities (RCE, Prompt Injection) for educational purposes. **DO NOT DEPLOY IN PUBLIC PRODUCTION ENVIRONMENTS.** Always run within the provided isolated Docker container.
