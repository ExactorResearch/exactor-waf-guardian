# Exactor WAF Guardian

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](#license)
[![Powered by](https://img.shields.io/badge/Engine-Exactor%20Core%20(Rust)-orange.svg)](https://github.com/ExactorResearch/exactor-accelerator)
[![Latency](https://img.shields.io/badge/Latency-0.05ms-brightgreen.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-100k%2B%20req%2Fs-blue.svg)](#benchmarks)
[![Live Demo](https://img.shields.io/badge/Demo-Interactive%20App-purple.svg)](https://waf.exactor.ai)

**Exactor WAF Guardian** is a production-grade Web Application Firewall (WAF) demonstration showcasing **Exactor Accelerator** in real-time cybersecurity environments.

It solves the fundamental dilemma of modern application security: **combining deep AI reasoning with sub-millisecond network SLAs (0.05 ms) and zero marginal API cost.**

---

## 🌐 Live Interactive Demo

Test the live interactive WAF simulator in your browser:  
👉 **[Launch WAF Guardian Live](https://waf.exactor.ai)**

* Simulate high-volume benign and malicious HTTP traffic (SQL Injection, XSS, Path Traversal, Bot attacks).
* Watch the real-time latency counter execute decisions in **0.05 ms**.
* Inspect the dual output: **Action (`ALLOW` / `BLOCK`) + Causal Boolean Proof**.

---

## The Challenge with AI in Modern WAFs

| Approach | Latency (TTFB Impact) | Operational Cost | Resilience to Novel Zero-Days | Explainability |
| :--- | :--- | :--- | :--- | :--- |
| **Traditional RegEx WAF** | Fast (1–5 ms) | Zero API cost | Poor (Rigid rules, high false positives) | Hard-coded rules |
| **Cloud LLM / API WAF** | **500–1,200 ms** (Unacceptable) | **Linear API cost** ($10k+/month) | High cognitive flexibility | Probabilistic / Opaque |
| **Exactor WAF Guardian** | **0.05 ms** (Fast-Path local) | **Zero marginal cost** (99.9% local) | **High** (Autonomous oracle escalation) | **Deterministic Boolean Proof** |

---

## Architecture: How It Works

Exactor WAF Guardian operates as an inline reverse proxy or Envoy/Nginx sidecar:

```text
[ Inbound HTTP Request ]
          │
          ▼
 [ 1. Feature Binarizer ] ─── (Header entropy, SQL keywords, payload length, IP rep)
          │
          ▼
 ┌────────────────────────────────────────────────────────┐
 │ 2. Exactor Fast-Path (Rust Core in Memory)             │
 │    - Evaluates Boolean Hypercube in 0.05 ms            │
 └───────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
 [ Known Match (99.9%) ]           [ Novel Pattern / Anomaly (0.1%) ]
        │                                 │
        ▼                                 ▼
 [ Instant Action + Proof ]        [ Oracle Escalation (Jev / LLM) ]
 (ALLOW / BLOCK)                          │
                                          ▼
                                   [ SQLite WAL Ledger ]
                                          │
                                          ▼
                                   [ Hot Boolean Minimization ]
                                   (Compiled into next Fast-Path iteration)
```

### The Dual Output (Glass Box)
For every evaluated request, Exactor WAF Guardian outputs both the decision and the mathematical proof:

```json
{
  "request_id": "req_84920481",
  "action": "BLOCK",
  "latency_ms": 0.048,
  "execution_path": "FAST_PATH_LOCAL",
  "causal_proof": "(contains_sql_tokens AND payload_entropy > 4.2 AND user_agent_empty) -> ACTION_BLOCK",
  "oracle_consulted": false
}
```

---

## Quickstart

### Prerequisites
* Python 3.9+ (or Rust 1.80+)
* pip

### Installation & Launching Local Dashboard (Port 8002)

```bash
git clone https://github.com/ExactorResearch/exactor-waf-guardian.git
cd exactor-waf-guardian
pip install -r requirements.txt

# Launch interactive web dashboard
python run_web.py
```

Once running, access the local dashboard at **`http://localhost:8002`**.
* 🛡️ **Interactive Traffic Inspector**: Test custom payloads or OWASP Top 10 presets and view live AST tokens and KaTeX mathematical proofs.
* ⚔️ **Live Multi-Agent Duel**: Real-time side-by-side race between Exactor, Pure JEV, and Regex across simulated attack streams.
* 📊 **Benchmark Suite & Visualizations**: Interactive sliders and log-scale metrics for throughput, latency quantiles, and cloud cost.

---

## CLI Usage & Benchmarks

### Single Payload Inspection
```bash
python run_cli.py --path "/api/login" --query "username=admin' OR '1'='1'--"
```

### Run Multi-Agent Benchmark Suite
```bash
python run_benchmark.py 100
```

### Run Unit Tests
```bash
python -m pytest -v
```

---

## Project Structure

```text
exactor-waf-guardian/
├── exactor_waf/
│   ├── ast_lexer.py         # HTTP AST token extractor
│   ├── engine.py            # SAT Invariant & Exactor Accelerator Fast-Path
│   ├── web/                 # Interactive web dashboard & API server (Port 8002)
│   └── attack_sim.py        # Traffic generator (benign vs OWASP attack vectors)
├── run_web.py               # Launch dashboard
├── run_cli.py               # Command-line inspection tool
├── run_benchmark.py         # Multi-agent benchmark suite
├── EXACTOR_METHODOLOGY.md   # Mathematical invariant specification
└── README.md
```

---

## Integration as a Middleware

You can embed Exactor WAF Guardian into any Python web service (FastAPI, Flask, Starlette):

```python
from fastapi import FastAPI, Request
from exactor_waf.engine import WafEngine

app = FastAPI()
waf = WafEngine()

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    decision = waf.evaluate(request)
    if decision.action == "BLOCK":
        return Response(
            content=f"Blocked by Exactor WAF: {decision.causal_proof}", 
            status_code=403
        )
    return await call_next(request)
```

---

## 📅 Enterprise Evaluation & Demo Scheduling

Ready to eliminate inference latency and cloud API costs for your security and application infrastructure?

- **Schedule a 15-Min Architecture Review:** [Book Directly on Cal.com](https://cal.com/exactor-tech)
- **Submit Workload Requirements:** [Open Tally / Typeform Assessment](https://tally.so/r/w2xD4P)
- **Direct Commercial Inquiries:** [`contact@exactor.tech`](mailto:contact@exactor.tech)

---

## License

Dual-licensed under [MIT](LICENSE) or [Apache 2.0](LICENSE-APACHE).

