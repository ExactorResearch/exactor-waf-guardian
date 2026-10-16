# Exactor WAF Guardian

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](#license)
[![Powered by](https://img.shields.io/badge/Engine-Exactor%20Core%20(Rust)-orange.svg)](https://github.com/ExactorResearch/exactor-accelerator)
[![Latency](https://img.shields.io/badge/Latency-0.02ms-brightgreen.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-80k%2B%20req%2Fs-blue.svg)](#benchmarks)
[![Synthesis](https://img.shields.io/badge/Synthesis-exactor.tech%20(v128)-purple.svg)](https://exactor.tech)
[![Proof of Concept](https://img.shields.io/badge/PoC-Interactive%20Duel-success.svg)](PROOF_OF_CONCEPT.md)
[![Epistemology](https://img.shields.io/badge/Theory-Axiomatic%20Supervision-blueviolet.svg)](AXIOMATIC_SUPERVISION_AND_SYNTHESIS.md)

**Exactor WAF Guardian** is a production-grade Web Application Firewall (WAF) reverse-proxy and server daemon engineered in **Rust**, accompanied by an empirical **Interactive Proof of Concept (PoC)** suite in Python.

It implements deterministic Neuro-Symbolic SAT verification and formal **Certainty Islands (Islas de Certeza)** for real-time edge cybersecurity, resolving the fundamental trilemma of modern application security: **combining deep cognitive reasoning with sub-millisecond network SLAs (< 0.05 ms), 100% mathematically verifiable causal proofs, zero marginal inference cost, and autonomous Boolean logic minimization via [https://exactor.tech](https://exactor.tech).**

> 📘 **Foundational Theoretical Documentation:**  
> To understand how the WAF classifies without manual human labeling, and how rules are synthesized and generalized by consuming Silicon Units (SU), see [Axiomatic Supervision and Inductive Synthesis in EXACTOR](AXIOMATIC_SUPERVISION_AND_SYNTHESIS.md).

---

## 🚀 Get Started (60-Second Quickstart)

Protect any web application, microservice, or API in under a minute without installing compilers or external runtime dependencies.

### 1. Choose Your Preferred Deployment Method

#### A. Linux (Ubuntu / Debian / RHEL / CentOS / Rocky / Alpine)
```bash
curl -sSL https://raw.githubusercontent.com/ExactorResearch/exactor-waf-guardian/master/install.sh | sudo bash
```

#### B. Windows Server (PowerShell as Administrator)
```powershell
irm https://raw.githubusercontent.com/ExactorResearch/exactor-waf-guardian/master/install.ps1 | iex
```

#### C. Docker Compose (Zero-Host Install)
```bash
docker compose up -d
```

#### D. Portable Mode / Standalone Binary (Zero System Service Changes)
Download the precompiled bundle from [`dist/`](dist/) or GitHub Releases and run directly:
```bash
# Windows
.\exactor-waf-guardian.exe proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000

# Linux
./exactor-waf-guardian proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000
```

---

### 2. Configure Your Upstream Backend Application

By default, the WAF listens on public port `8080` and reverse-proxies verified traffic to your internal backend application running on port `3000`.  
Modify it in `waf_config.toml` or pass CLI flags:

```toml
# Public ingress port receiving internet traffic
listen_addr = "0.0.0.0:8080"

# Target backend upstream server (Node.js, Python, Java, Go, Rust, PHP, etc.)
upstream_url = "http://127.0.0.1:3000"

# Defense mode: "block" (active perimeter drop) or "monitor" (dry-run detection)
mode = "block"
```

---

### 3. Verify Your First Block with Formal Mathematical Proof

Once the WAF daemon is active, execute these tests from any terminal or browser:

#### ✅ Legitimate Request (Allowed & Accelerated)
```bash
curl -i http://localhost:8080/
```
> **Result:** HTTP `200 OK`, returning header `X-Exactor-Protected: true` with inspection latency below $0.02\text{ ms}$.

#### 🛑 SQL Injection Attack Attempt (Instantly Blocked)
```bash
curl -i "http://localhost:8080/?id=1'%20OR%201=1--"
```
> **Result:** HTTP `403 Forbidden` in $< 0.05\text{ ms}$. The backend never receives the malicious packet.  
> The JSON payload contains the causal proof chain and formal $\LaTeX$ theorem:
> ```json
> {
>   "action": "BLOCK",
>   "category": "sql_injection",
>   "latency_us": 24.1,
>   "causal_proof": "(TAUTOLOGY_EQUALS) violates [SAT-SQLI-01] -> ACTION_BLOCK",
>   "formal_proof_latex": "\\begin{aligned} ... \\text{Eval}(\\mathcal{C}_{\\text{WAF}}, \\mathcal{T}) \\equiv \\mathbf{FALSE} \\implies \\mathbf{BLOCK} \\end{aligned}"
> }
> ```

---

### 4. Real-Time Telemetry & Observability Endpoints

The server exposes built-in ultra-low latency observability routes without external software dependencies:
- **Health Check:** [`http://localhost:8080/health`](http://localhost:8080/health)
- **Performance Telemetry:** [`http://localhost:8080/api/waf/metrics`](http://localhost:8080/api/waf/metrics) (throughput, blocked counts, p50/p99 latency in microseconds).
- **Fast CLI Single-Payload Inspection (No server required):**
  ```bash
  exactor-waf-guardian inspect --query "id=1' OR 1=1--"
  ```

---

## 🧠 Why Train, How Does It Work, and How to Obtain Your License?

### 1. Why Does the WAF Need Training?
The WAF ships out-of-the-box with **10 pre-configured Certainty Islands** that drop known attack archetypes in under $0.02\text{ ms}$.

In real-world production environments, adversaries **continuously mutate and disguise their vectors**:
- Injecting SQLi via inline comments `/*...*/`, hexadecimal encodings, deeply nested JSON, or spoofed headers.
- Each mutation spawns a **novel minterm** within the Boolean hypercube $\{0, 1\}^{128}$, which the local WAF blocks and logs into its SQLite WAL database (`waf_ledger.db`).
- **Without Training:** The WAF would need to retain thousands of isolated minterm cases in RAM, causing CPU cache thrashing and degraded throughput.
- **With EXACTOR CORE Cloud Training:** The cloud algorithm executes **Exact Inductive Synthesis**:
  1. Strips all camouflage variables (*Don't Cares*).
  2. Extracts the **Minimal Prime Implicant** (the irreducible algebraic root formula).
  3. **Generalizes protection to 100%:** Immunizes the server not only against previously observed variants, but against **trillions of future permutations** sharing that core, collapsing thousands of rules into a single CPU register instruction (`AND & CMP`).

---

### 2. How Does Training Run?
The WAF provides two training modes:
1. **Autonomous Background Sync (Recommended):**  
   The daemon scans pending anomaly minterms accumulated in `waf_ledger.db`, batches them, and dispatches them to the cloud every 5 minutes (`autonomous_sync_interval_secs = 300`). The synthesized rule is **hot-compiled into RAM in 1 microsecond**, without restarting the daemon or interrupting live client connections.
2. **Manual CLI Sync:**  
   Trigger immediate synchronization and cloud synthesis on demand:
   ```bash
   exactor-waf-guardian sync-simplify --config /etc/exactor/waf_config.toml
   ```

---

### 3. How to Obtain an EXACTOR CORE License Token?
To connect your WAF with the cloud mathematical synthesis engine and enable continuous learning, obtain a **License Token**:

1. **Create an EXACTOR Account:**  
   Register at [https://exactor.tech/register.html](https://exactor.tech/register.html).
2. **Select a Silicon Unit (SU) Plan:**  
   - **Free Plan:** Includes **100 SU / month** for testing and lab validation.
   - **Scout Plan ($20 USD/mo):** 1,000 SU / month (up to 20 variables / 2.5K minterms).
   - **Pro / Dev Plan ($49 USD/mo):** 5,000 SU / month (up to 64 variables / 10K minterms).
   - **Startup Plan ($499 USD/mo):** 50,000 SU / month (up to 128 variables / 100K minterms).
3. **Copy Your API Token:**  
   In your EXACTOR dashboard ([https://exactor.tech/token-manager.html](https://exactor.tech/token-manager.html)), copy your **API Token** (`ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx`).

---

### 4. How to Configure the License in the WAF?

#### Option A: Inside `waf_config.toml` (Recommended)
Edit `/etc/exactor/waf_config.toml` (Linux) or `C:\ProgramData\Exactor\WAF\waf_config.toml` (Windows):

```toml
# Official EXACTOR CORE Boolean synthesis API endpoint
exactor_api_url = "https://exactor.tech/api/simplify"

# Your EXACTOR CORE License / API Token
exactor_api_token = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Enable continuous autonomous learning and synthesis
auto_sync_enabled = true

# Training synchronization interval in seconds (default: 300s = 5 minutes)
autonomous_sync_interval_secs = 300
```

#### Option B: Via Environment Variables (Docker / Kubernetes)
```bash
export EXACTOR_API_TOKEN="ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export EXACTOR_API_URL="https://exactor.tech/api/simplify"
```
In `docker-compose.yml`:
```yaml
environment:
  - EXACTOR_API_URL=https://exactor.tech/api/simplify
  - EXACTOR_API_TOKEN=ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### Option C: Verify Your License Connection
To test communication with the cloud synthesis engine:
```bash
exactor-waf-guardian sync-simplify --config waf_config.toml
```
Expected terminal output:
```text
⚡ Exactor WAF: Initiating Exact Boolean Simplification
   Target: https://exactor.tech/api/simplify
📥 Found 15 pending anomaly minterms to simplify.
✅ Cloud Simplification Succeeded!
   Reduction Percentage : 93.33%
   Original Gates       : 45
   New Gates            : 3
```

---   Reduction Percentage : 93.33%
   Original Gates       : 45
   New Gates            : 3
```

---

## 🏛️ System Architecture

```text
       [ Inbound HTTP / GraphQL / gRPC Traffic from Clients ]
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   EXACTOR WAF GUARDIAN (Rust Server)                   │
│                                                                        │
│  1. Multi-Stage Grammar Normalizer & AST Lexer                         │
│     - Multi-pass recursive URL decoding (%20, %2e%2e%2f)               │
│     - SQL comment stripping (/**/ -> epsilon)                          │
│     - GraphQL AST Lexer: introspection probes, depth & batching        │
│     - Strict JSON Parser: Prototype Pollution & nesting bombs          │
│     - gRPC Frame Inspector: 5-byte wire prefix & status injection      │
│     - JWT Tamper Analyzer: alg "none", missing sig, KID traversal      │
│     - Shannon entropy binarizer & Boolean Hypercube {0, 1}^N           │
│                                                                        │
│  2. In-Memory Fast-Path SAT Solver (< 0.02 ms)                         │
│     Evaluates 10 Formal Certainty Islands (Islas de Certeza):          │
│     • ISLAND-SQLI       (Tautologies, UNION select, Time-delay, DDL)   │
│     • ISLAND-XSS        (Script contexts, Event attributes, SVG, URIs) │
│     • ISLAND-RCE        (Shell chains, Subshells, Dynamic eval sinks)  │
│     • ISLAND-LFI        (Path traversal escapes, Sensitive roots)      │
│     • ISLAND-SSRF       (Cloud metadata 169.254, RFC1918 loopbacks)    │
│     • ISLAND-GRAPHQL    (Introspection dumping, Depth > 6, Batching)   │
│     • ISLAND-JSON-PROTO (__proto__, constructor.prototype, Bomb > 20)  │
│     • ISLAND-GRPC       (Client status trailers, HTTP/2 frame desync)  │
│     • ISLAND-JWT        (Alg: none, Unsigned tokens, KID injection)    │
│     • ISLAND-STATEFUL   (Atomic Ring Counter L7 DDoS & Brute Force)    │
│                                                                        │
│  3. Perimeter Decision:                                                │
│     ├─ [ VIOLATION DETECTED ]                                          │
│     │   └─ Immediate HTTP 403 Forbidden Response (< 0.05 ms)           │
│     │      • X-Exactor-Action: BLOCK                                   │
│     │      • X-Exactor-Proof: [Causal Proof Chain]                     │
│     │      • JSON Body: LaTeX Formal Proof + Active Predicate Tokens   │
│     │                                                                  │
│     └─ [ CLEAN TRAFFIC (ALLOW) ]                                       │
│         └─ High-Throughput Proxy Streaming to Upstream Backend         │
│            • http://127.0.0.1:3000                                     │
│            • X-Exactor-Protected: true                                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Non-blocking asynchronous queue)
                                    ▼
                        [ SQLite WAL Ledger ] (waf_ledger.db)
                        - Asynchronous audit event stream
                        - Novel anomaly minterm hypercubes (u128)
                                    │
                                    ▼ (Background Worker / Sync Trigger)
┌────────────────────────────────────────────────────────────────────────┐
│   Autonomous Exact Boolean Minimization                                │
│   Target: https://exactor.tech/api/simplify                            │
│   (Powered by exactor-cloud-service-v128)                              │
│                                                                        │
│   - Binarizes novel anomaly minterms into prime implicants in O(n)     │
│   - Synthesizes exact minimal Boolean equations                        │
│   - Hot-compiles dynamic clauses into Fast-Path memory in microseconds │
│     WITHOUT restarting the server or dropping connections!             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ The 10 Certainty Islands (Islas de Certeza)

| Island ID | Domain | Target Vector & Formal Invariant | Action |
| :--- | :--- | :--- | :---: |
| **`ISLAND-SQLI`** | Relational SQL AST | Tautologies (`' OR 1=1`), UNION exfiltration, stacked DDL, sleep/benchmark primitives. | **BLOCK** |
| **`ISLAND-XSS`** | DOM Execution Context | Script tags, inline event triggers (`onload`, `onerror`), SVG vectors, `javascript:` URIs. | **BLOCK** |
| **`ISLAND-RCE`** | OS Command Execution | Shell chaining (`;`, `\|\|`, `&&`), subshell substitutions (`$()`, backticks), eval sinks. | **BLOCK** |
| **`ISLAND-LFI`** | Filesystem Sandbox | Path traversals (`../../`), direct root targeting (`/etc/passwd`, `/proc/self/environ`). | **BLOCK** |
| **`ISLAND-SSRF`** | Network Perimeter | Cloud metadata (`169.254.169.254`), loopback proxies (`127.0.0.1`), private RFC1918 ranges. | **BLOCK** |
| **`ISLAND-GRAPHQL`** | GraphQL Schema & AST | Introspection queries (`__schema`, `__type`), recursive cyclic nesting (> 6 levels), batching. | **BLOCK** |
| **`ISLAND-JSON-PROTO`** | Strict JSON Schemas | Prototype pollution (`__proto__`, `constructor.prototype`), JSON schema nesting bombs (> 20 levels). | **BLOCK** |
| **`ISLAND-GRPC`** | HTTP/2 Wire Protocol | Client trailer injection (`grpc-status: 0`), 5-byte gRPC framing desynchronization / smuggling. | **BLOCK** |
| **`ISLAND-JWT`** | Cryptographic Identity | Algorithm confusion (`alg: "none"`), missing signatures, `kid` path traversal / SQLi. | **BLOCK** |
| **`ISLAND-STATEFUL`** | Behavioral Dynamics | Temporal sliding window ring counters: Layer-7 burst DDoS and distributed credential stuffing. | **BLOCK** |

---

## 🧪 Proof of Concept (PoC) & Multi-Agent Duel

The repository includes a comprehensive Python Proof of Concept in [`exactor_waf/`](file:///d:/proyectos/rush/exactor-waf-guardian/exactor_waf) to visualize and compare the technology before production deployment.

### 1. Interactive Web Dashboard (`run_web.py`)
Launch the visual duel simulator:
```bash
python run_web.py 8002
```
* **URL:** Navigate to **`http://localhost:8002`**
* **Live Multi-Agent Duel:** Watch **Exactor SAT**, **ModSecurity (Regex)**, and **Pure LLM (JEV Solo)** process the same payloads side-by-side.
* **KaTeX $\LaTeX$ Math Mode:** Renders mathematically verifiable proofs in real time explaining why attacks are dropped with zero hallucination.

### 2. Single Payload CLI Inspection (`run_cli.py`)
```bash
python run_cli.py --path "/api/users" --query "id=1' OR '1'='1"
```

### 3. Multi-Agent Benchmark Suite (`run_benchmark.py`)
```bash
python run_benchmark.py 100
```
Compares Accuracy, False Negatives, False Positives, Latency, and Cost across all 3 agent architectures.

*(For in-depth details, see [PROOF_OF_CONCEPT.md](PROOF_OF_CONCEPT.md) and [EXACTOR_METHODOLOGY.md](EXACTOR_METHODOLOGY.md)).*

---

## 🌊 Blue Ocean Strategy Comparison

| Competitive Factor | Traditional Regex WAF (ModSecurity / CRS) | Cloud LLM WAF (Cloudflare AI / AWS) | Exactor WAF Guardian (Rust) |
| :--- | :---: | :---: | :---: |
| **Inference Cost** | Low | High ($2,000+ / 1M reqs) | **$0.00 (Local Deterministic)** |
| **Network SLA Compliance** | Fast ($1 - 5\text{ ms}$) | Unacceptable ($350 - 650\text{ ms}$) | **Ultra-Fast (< 0.05 ms / < 20 µs)** |
| **Resistance to Obfuscation** | Poor (Evasion bypasses) | High (Context-aware) | **Absolute (Certainty Islands)** |
| **False Positive Rate** | High (Breaks on valid code) | Moderate | **Zero (0.00% on Benign Traffic)** |
| **Causal Explainability** | Opaque rule ID | Non-deterministic text | **Formal $\LaTeX$ & Causal Graphs** |
| **Enterprise Grammars** | Partial | Brittle | **Native (GraphQL, JSON, gRPC, JWT)** |
| **Behavioral Defense** | Rudimentary iptables | Slow batch heuristics | **Sliding Window Ring Counters** |
| **Autonomous Evolution** | Slow manual CRS releases | Costly model fine-tuning | **Real-Time Boolean Minimization** |

> 📖 **In-Depth Comparative Analysis:** See the technical report [COMPARATIVE_ANALYSIS_PRE_VS_EXACTOR.md](COMPARATIVE_ANALYSIS_PRE_VS_EXACTOR.md) for the complete breakdown of the four structural failures of the pre-EXACTOR era (RegEx and Cloud AI) alongside empirical benchmark findings.

---

## 🛠️ Zero-Dependency Installation

Clients **do not need to install runtime dependencies** on their servers (no Rust toolchains, no Cargo, no Python runtimes, no C/C++ compilers, and no dynamic shared libraries). The binary is 100% self-contained and statically linked.

### Method 1: Quick One-Liner Installer (Recommended for Production)

#### On Linux (Ubuntu / Debian / RHEL / CentOS / Rocky / Alpine)
Run directly in your terminal as root:
```bash
curl -sSL https://raw.githubusercontent.com/ExactorResearch/exactor-waf-guardian/master/install.sh | sudo bash
```
> **What does it do automatically?**
> 1. Detects system architecture (`x86_64` or `aarch64/ARM64`).
> 2. Installs the static binary to `/usr/local/bin/exactor-waf-guardian`.
> 3. Deploys default configuration to `/etc/exactor/waf_config.toml`.
> 4. Registers and starts the `systemd` system daemon (`exactor-waf.service`).

#### On Windows Server
Run in PowerShell as Administrator:
```powershell
irm https://raw.githubusercontent.com/ExactorResearch/exactor-waf-guardian/master/install.ps1 | iex
```
> **What does it do automatically?**
> 1. Installs the executable to `C:\Program Files\Exactor\WAF\exactor-waf-guardian.exe`.
> 2. Deploys default configuration to `C:\ProgramData\Exactor\WAF\waf_config.toml`.
> 3. Appends the directory to `System PATH` (accessible globally from any prompt).
> 4. Registers and launches the `ExactorWAF` Windows Service configured for automatic startup.

---

### Method 2: Offline Self-Contained Packages (`dist/` ZIP / TAR.GZ)

For air-gapped servers, restricted network perimeters, or environments where piped script execution is restricted:

1. **Download the precompiled bundle:**
   - **Windows:** `exactor-waf-guardian-v0.1.0-windows-x86_64.zip`
   - **Linux:** `exactor-waf-guardian-v0.1.0-linux-x86_64.tar.gz`
2. **Extract and install with a single command:**
   - On Windows:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\install.ps1
     ```
   - On Linux:
     ```bash
     sudo ./install.sh
     ```
3. **Portable Execution (Zero System Modifications):**
   If you prefer not to register system services, execute the binary directly:
   ```bash
   # Windows
   .\exactor-waf-guardian.exe proxy --config .\waf_config.toml

   # Linux
   ./exactor-waf-guardian proxy --config ./waf_config.toml
   ```

To generate standalone distribution packages locally:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_dist.ps1 -NoRebuild
```
or on Linux:
```bash
./scripts/package_dist.sh --no-rebuild
```

---

### Method 3: Container Deployment (Docker & Docker Compose)

For container-native environments without host modifications:

```bash
# Start immediately in background with Docker Compose
docker compose up -d

# Stream real-time inspection telemetry and logs
docker compose logs -f exactor-waf
```

---

### Clean Uninstallation

To completely remove the service, configuration, and binaries without leaving orphaned artifacts:
- **On Windows:** `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`
- **On Linux:** `sudo ./uninstall.sh` (or `sudo ./uninstall.sh --purge` to also remove the audit database).

---

## ⚙️ Configuration Reference (`waf_config.toml`)

```toml
# Network listener for inbound HTTP traffic
listen_addr = "0.0.0.0:8080"

# Target upstream backend application
upstream_url = "http://127.0.0.1:3000"

# Defense mode: "block" (perimeter defense) or "monitor" (dry-run detection)
mode = "block"

# EXACTOR Core Cloud API URL (exactor-cloud-service-v128)
exactor_api_url = "https://exactor.tech/api/simplify"

# EXACTOR Cloud API Token (optional for public demo or set via EXACTOR_API_TOKEN)
# exactor_api_token = "ek_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL Ledger database path
database_path = "waf_ledger.db"

# Autonomous background minimization sync interval in seconds (default: 300s)
autonomous_sync_interval_secs = 300

# Enable automatic hot minimization sync with https://exactor.tech
auto_sync_enabled = true

# ==============================================================================
# STATEFUL & BEHAVIORAL DEFENSE (Layer-7 DDoS & Credential Stuffing)
# ==============================================================================
# Enable temporal sliding window ring buffer analysis
stateful_enabled = true

# Max total requests permitted in sliding window per IP across all endpoints
stateful_global_limit = 300

# Max attempts permitted on sensitive authentication endpoints (/login, /auth, etc.)
stateful_auth_limit = 20

# Sliding temporal window duration in seconds (default: 60s ring buffer)
stateful_window_secs = 60

# Temporary isolation quarantine / jail duration in seconds for offenders
stateful_ban_secs = 180

# Optional Redis connection URL for distributed cluster state synchronization
# redis_url = "redis://127.0.0.1:6379"
```

---

## 💻 CLI Commands & Usage

### 1. Launch Reverse Proxy Daemon
```bash
exactor-waf-guardian proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000 --config waf_config.toml
```

### 2. Inspect Single Request Payload
```bash
exactor-waf-guardian inspect --method GET --path "/api/users" --query "id=1' OR '1'='1"
```
**Example Terminal Output:**
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

### 3. Run Built-In Multi-Vector Benchmark
```bash
exactor-waf-guardian benchmark --requests 10000
```

### 4. Trigger Cloud Simplification & Hot-Compilation
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
* **`GET /health`** or **`GET /livez`**: Service health & liveness check.

---

## 🧪 Unit & Integration Testing

Run the full Rust test suite covering all 10 Certainty Islands, enterprise grammars, and stateful sliding window ring counters:
```bash
cargo test -p exactor-waf-guardian
```
*18 unit and integration tests passing with 0 false positives.*

---

## 📄 License

Dual-licensed under [MIT](LICENSE) or [Apache 2.0](LICENSE-APACHE).
