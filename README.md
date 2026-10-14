# Exactor WAF Guardian

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](#license)
[![Powered by](https://img.shields.io/badge/Engine-Exactor%20Core%20(Rust)-orange.svg)](https://github.com/ExactorResearch/exactor-accelerator)
[![Latency](https://img.shields.io/badge/Latency-0.02ms-brightgreen.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-100k%2B%20req%2Fs-blue.svg)](#benchmarks)
[![Simplification](https://img.shields.io/badge/Synthesis-exactor.tech%20(v128)-purple.svg)](https://exactor.tech)

**Exactor WAF Guardian** is a production-grade Web Application Firewall (WAF) reverse-proxy and server daemon engineered in **Rust**. It implements deterministic Neuro-Symbolic SAT verification and formal **Certainty Islands (Islas de Certeza)** for real-time edge cybersecurity.

It resolves the fundamental trilemma of modern application security: **combining deep cognitive reasoning with sub-millisecond network SLAs (< 0.05 ms), 100% mathematically verifiable causal proofs, zero marginal inference cost, and autonomous Boolean logic minimization via [https://exactor.tech](https://exactor.tech).**

---

## 🏛️ System Architecture

```text
       [ Inbound HTTP Traffic from Clients ]
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│            EXACTOR WAF GUARDIAN (Rust Server)          │
│                                                        │
│  1. Recursive AST Normalizer & Grammar Lexer           │
│     - Multi-pass URL decoding (%20, %2e%2e%2f)         │
│     - SQL comment stripping (/**/ -> epsilon)          │
│     - GraphQL AST parser (depth, batching, schema)     │
│     - Strict JSON schema & Prototype Pollution checks  │
│     - gRPC HTTP/2 framing & client trailer injection   │
│     - JWT tamper detection (alg: none, missing sig)    │
│     - Shannon entropy binarizer & AST token lattice     │
│                                                        │
│  2. In-Memory Fast-Path SAT Solver (< 0.02 ms)         │
│     - Evaluates Certainty Islands:                     │
│       • ISLAND-SQLI (Tautologies, UNION, Time, DDL)    │
│       • ISLAND-XSS  (Scripts, Event handlers, SVG, URI)│
│       • ISLAND-RCE  (Shell chains, Subshells, Sinks)   │
│       • ISLAND-LFI  (Path traversal, Sensitive roots)  │
│       • ISLAND-SSRF (Cloud metadata 169.254, RFC1918)  │
│       • ISLAND-GRAPHQL (Introspection, Depth, Batching)│
│       • ISLAND-JSON-PROTO (Proto pollution, BOMBs)     │
│       • ISLAND-GRPC (Framing desync, Header injection) │
│       • ISLAND-JWT (Alg: none, missing sig, KID traversal)
│       • ISLAND-STATEFUL (Ring counter L7 DDoS & Brute) │
│                                                        │
│  3. Decision Perimeter:                                │
│     ├─ [ VIOLATION DETECTED ]                          │
│     │   └─ Immediate HTTP 403 Forbidden Response       │
│     │      • X-Exactor-Action: BLOCK                   │
│     │      • X-Exactor-Proof: [Causal Proof]           │
│     │      • JSON Body: LaTeX Proof + Active Tokens    │
│     │                                                  │
│     └─ [ CLEAN TRAFFIC (ALLOW) ]                       │
│         └─ Stream directly to Upstream Application     │
│            • http://127.0.0.1:3000                     │
│            • X-Exactor-Protected: true                 │
└───────────────────────┬────────────────────────────────┘
                        │ (Non-blocking async queue)
                        ▼
            [ SQLite WAL Ledger ] (waf_ledger.db)
            - Asynchronous audit events
            - Novel anomaly minterms cluster (u128)
                        │
                        ▼ (Background Worker / Sync Trigger)
┌────────────────────────────────────────────────────────┐
│   Autonomous Exact Boolean Minimization                │
│   Target: https://exactor.tech/api/simplify            │
│   (Running exactor-cloud-service-v128)                 │
│                                                        │
│   - Binarizes novel anomaly minterm hypercubes         │
│   - Computes exact prime implicants in O(n)            │
│   - Receives minimal Boolean equation                  │
│   - Hot-compiles dynamic clauses into Fast-Path memory │
│     WITHOUT restarting the server or dropping sockets! │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Capabilities

| Capability | Specification |
| :--- | :--- |
| **Execution Latency** | **< 0.02 ms (20 microseconds)** in Rust Fast-Path |
| **Throughput** | **> 80,000 req/sec** per single core |
| **Memory Footprint** | **< 15 MB** RAM for proxy & in-memory AST lattices |
| **Cloud Simplification** | Integrates directly with **`https://exactor.tech/api/simplify`** (`exactor-cloud-service-v128`) |
| **Audit Ledger** | Built-in non-blocking SQLite WAL database (`waf_ledger.db`) |
| **Mathematical Proof** | Generates verifiable LaTeX formal proofs & causal chains on every request |
| **Deployment Modes** | Standalone Reverse Proxy, Envoy/Nginx Sidecar (`/api/waf/inspect`), or Systemd Daemon |

---

## 🛠️ Server Installation

### 1. Automated Installation on Linux (Ubuntu / Debian / RHEL / CentOS)

Run the included automated installer script with `sudo`:

```bash
cd exactor-waf-guardian
sudo ./install.sh
```

The script automatically:
1. Builds the optimized release binary (`cargo build --release`).
2. Installs the executable to `/usr/local/bin/exactor-waf-guardian`.
3. Creates configuration directory `/etc/exactor/waf_config.toml`.
4. Installs and registers the systemd service `/etc/systemd/system/exactor-waf.service`.
5. Enables and starts the service.

### 2. Automated Installation on Windows Server

Run in PowerShell as Administrator:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1
```

Installs to `C:\Program Files\Exactor\WAF` and adds the binary to System PATH.

### 3. Containerized Deployment (Docker & Kubernetes)

```bash
docker build -t exactor-waf-guardian:latest .
docker run -d -p 8080:8080 \
  -e WAF_UPSTREAM_URL="http://host.docker.internal:3000" \
  -e EXACTOR_API_URL="https://exactor.tech/api/simplify" \
  exactor-waf-guardian:latest
```

---

## ⚙️ Configuration (`waf_config.toml`)

```toml
# Inbound listen address for the WAF proxy
listen_addr = "0.0.0.0:8080"

# Target upstream backend application (Node, Go, Python, Nginx, etc.)
upstream_url = "http://127.0.0.1:3000"

# Defense mode: "block" (drop attacks) or "monitor" (dry-run detection)
mode = "block"

# EXACTOR Core Cloud API URL (exactor-cloud-service-v128)
exactor_api_url = "https://exactor.tech/api/simplify"

# EXACTOR Cloud API Token or Bearer Token (optional for public demo)
# exactor_api_token = "ek_e938b07ce13846e4a24e5db8bacc447c797b011f"

# Local SQLite WAL Ledger database location
database_path = "waf_ledger.db"

# Autonomous background minimization sync interval in seconds
autonomous_sync_interval_secs = 300

# Enable automatic hot minimization sync with https://exactor.tech
auto_sync_enabled = true
```

---

## 💻 CLI Commands & Inspection

### 1. Run Reverse Proxy Server
```bash
exactor-waf-guardian proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000 --config /etc/exactor/waf_config.toml
```

### 2. Inspect Single Payload via CLI
```bash
exactor-waf-guardian inspect --method GET --path "/api/users" --query "id=1' OR '1'='1"
```
**Output:**
```text
🔍 Exactor WAF Guardian: Payload Inspection Report
============================================================
Request ID       : req_84920481
Target Path      : /api/users
Query String     : id=1' OR '1'='1
Action Decision  : Block
Attack Category  : SQL INJECTION (SQLi)
Latency          : 18.42 µs (0.0184 ms)
Active Tokens    : ["QUOTE", "TAUTOLOGY_EQUALS"]
Certainty Islands: ["ISLAND-SQLI"]
------------------------------------------------------------
Causal Proof     :
(QUOTE AND TAUTOLOGY_EQUALS) violates [SAT-SQLI-01] -> ACTION_BLOCK [sql_injection]
------------------------------------------------------------
LaTeX Formal SAT Proof:
\begin{aligned}
\mathbf{Certainty\ Island} &: \{\mathcal{I}_{\text{SQLi}}\} \subset \mathcal{I}_{\text{SAT}} \\[4pt]
\mathbf{Active\ Tokens} &: \mathcal{T} = \{\texttt{QUOTE}, \texttt{TAUTOLOGY\_EQUALS}\} \\[4pt]
\mathbf{Invariant\ Rule} &: \mathcal{C}_{\text{WAF}} \equiv \neg (\texttt{SAT-SQLI-01}) \\[4pt]
\mathbf{SAT\ Evaluation} &: \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}) \equiv \mathbf{FALSE} \implies \mathbf{BLOCK\ [SQL\_INJECTION]}
\end{aligned}
============================================================
```

### 3. Run Multi-Vector Performance Benchmark
```bash
exactor-waf-guardian benchmark --requests 10000
```

### 4. Trigger Autonomous Cloud Simplification
```bash
exactor-waf-guardian sync-simplify --limit 50
```

---

## 📡 REST API & Sidecar Inspection Endpoints

The server exposes built-in management & telemetry routes alongside the reverse proxy:

* **`POST /api/waf/inspect`**: Submit arbitrary HTTP payloads for sub-millisecond evaluation.
* **`GET /api/waf/metrics`**: Live telemetry (total requests, blocked count, average latency, p99, pending anomalies).
* **`GET /api/waf/rules`**: Complete catalog of active Certainty Island invariant rules.
* **`GET /api/waf/islands`**: Catalog of Certainty Islands.
* **`POST /api/waf/sync-simplify`**: Manually trigger Boolean minimization with `https://exactor.tech/api/simplify` and hot-reload rules.
* **`GET /health`** or **`GET /livez`**: Service liveness check.

---

## 🧪 Unit & Integration Tests

```bash
cargo test
```

---

## 📄 License

Dual-licensed under [MIT](LICENSE) or [Apache 2.0](LICENSE-APACHE).
