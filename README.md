# Autonomous LLM-Enabled Multi-Agent Self-Healing Intrusion Detection and Prevention System for IoT Networks

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev)
[![LightGBM](https://img.shields.io/badge/ML-LightGBM%20%2B%20IsolationForest-orange.svg)](https://lightgbm.readthedocs.io)
[![Ollama](https://img.shields.io/badge/LLM-Qwen2.5--3B%20%2F%201.5B-purple.svg)](https://ollama.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, autonomous Intrusion Detection and Prevention System (IDS/IPS) specifically architected for Internet of Things (IoT) ecosystems. The platform combines real-time network flow telemetry ingestion (Suricata & Zeek), dual-engine machine learning (supervised **LightGBM** classifier + unsupervised **Isolation Forest** zero-day anomaly scoring), local **Large Language Model (LLM)** contextual threat reasoning (Qwen 2.5 via Ollama), autonomous **nftables** firewall mitigation, proactive self-healing service recovery, and full-stack observability with Promtail, Loki, Grafana, and a modern React 19 glassmorphism dashboard.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Key Capabilities & Innovations](#key-capabilities--innovations)
- [Autonomous Agents](#autonomous-agents)
- [Machine Learning Subsystem](#machine-learning-subsystem)
- [Prerequisites & System Requirements](#prerequisites--system-requirements)
- [Quick Start](#quick-start)
- [Service Ports & Topology](#service-ports--topology)
- [Environment Variable Configuration](#environment-variable-configuration)
- [Complete API & WebSocket Reference](#complete-api--websocket-reference)
- [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
- [Observability & Monitoring (Grafana + Loki)](#observability--monitoring-grafana--loki)
- [Threat Simulation & Live Verification](#threat-simulation--live-verification)
- [LLM Fine-Tuning & Model Management](#llm-fine-tuning--model-management)
- [Development & Local Testing](#development--local-testing)
- [Troubleshooting & FAQs](#troubleshooting--faqs)

---

## Architecture Overview

The system runs on a **consolidated five-agent asynchronous architecture** executed inside the FastAPI process using `asyncio` event loops and bounded, typed queues:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       IoT Network Traffic Sources                                        │
│                        Suricata (eve.json)  ◄───►  Zeek (conn.log / tsv)                                │
└────────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                     │
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     TrafficAgent (Log Tailer & Extractor)                               │
│       • Computes 17 Telemetry Features + Sliding Window Shannon Port Entropy                             │
│       • Broadcasts Live Telemetry Batches to WebSocket Subscribers                                      │
└───────────────────────────────────┬─────────────────────────────────┬───────────────────────────────────┘
                                    │ detection_queue                 │ anomaly_queue
                                    ▼                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AnalysisAgent (Dual ML Engine)                                       │
│       • LightGBM Supervised Classifier (99.35% Acc, 99.59% F1)                                         │
│       • Isolation Forest Unsupervised Zero-Day Anomaly Scorer                                           │
│       • Emits ThreatScores & Priority-Ranked AttackEvents (P1/P2/P3)                                    │
└────────────────────────────────────────────────────┬────────────────────────────────────────────────────┘
                                                     │ orchestrator_queue
                                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                LLMOrchestrator (Cognitive Coordinator)                                  │
│       • Merges Dual-Score Windows (500ms Aggregation Window)                                            │
│       • Contextual LLM Threat Reasoning via Local Qwen 2.5 (5s Timeout)                                 │
│       • Deterministic Fallback Rules (Critical >= 0.90, High >= 0.75, Med >= 0.65)                      │
│       • Dispatches Mitigation, Incident State Tracking, Campaign Correlation                            │
└───────────────────────┬─────────────────────────────────────────────┬───────────────────────────────────┘
                        │ prevention_queue / healing_queue            │ logging_queue
                        ▼                                             ▼
┌──────────────────────────────────────────────────┐  ┌───────────────────────────────────────────────────┐
│     ResponseAgent (Mitigation & Self-Healing)     │  │       ObservabilityAgent (Persistence & Reports)   │
│ • nftables Block / Rate-Limit / Device Isolation │  │ • Dual-Buffer Persistence (PostgreSQL + Syslog)   │
│ • IP Whitelist Protection & State File Sync      │  │ • Automated Daily / Weekly / Monthly Reports      │
│ • Automated Rule Expiry Sweep (60s loop)         │  │ • Computes Real-Time MTTD & MTTR Metrics          │
│ • Self-Healing Service Restarts + Health Probes  │  │ • Export to JSON & CSV Formats                    │
└──────────────────────────────────────────────────┘  └───────────────────────────────────────────────────┘
```

---

## Key Capabilities & Innovations

1. **Sub-Millisecond Threat Detection**: Parallel feature preprocessing and LightGBM classification achieves inference latency under 0.5ms per flow.
2. **Zero-Day Anomaly Detection**: Unsupervised Isolation Forest flags novel behavioral outliers that have no known signature or supervised label.
3. **Cognitive Explainability via Local LLM**: Qwen 2.5 generates natural-language threat assessments, blast-radius evaluations, and recommended remediation actions without cloud dependency.
4. **Deterministic Fallback Safety**: Seamless fallback to rule-based enforcement if the LLM engine is slow or offline, ensuring uninterrupted perimeter defense.
5. **Dynamic IoT Device Isolation**: Automatically marks compromised devices in PostgreSQL, adjusts firewall rules, and displays one-click isolation management in the UI.
6. **Self-Healing Recovery**: Automatically detects degraded services (Suricata, Zeek, Loki, Promtail, API), performs staged restarts with exponential backoff, and verifies service recovery.
7. **Complete Administrative Audit Logging**: Every manual device isolation, incident acknowledgment, and configuration tweak is persisted to `audit_logs` with IP and User-Agent telemetry.

---

## Autonomous Agents

The system consolidates security tasks into five specialized agents running concurrently:

| Agent | Module | Primary Responsibilities | Queues Consumed / Produced |
|---|---|---|---|
| **TrafficAgent** | `backend/agents/traffic_agent.py` | Asynchronously tails Suricata `eve.json` and Zeek `conn.log`, extracts 17 flow features, maintains recent flow buffers, and broadcasts 1Hz live telemetry batches. | **Produces:** `detection_queue`, `anomaly_queue` |
| **AnalysisAgent** | `backend/agents/analysis_agent.py` | Runs supervised LightGBM classification and Isolation Forest anomaly scoring in parallel. Handles baseline profiling and learning mode. | **Consumes:** `detection_queue`, `anomaly_queue`<br/>**Produces:** `risk_queue`, `orchestrator_queue` |
| **LLMOrchestrator** | `backend/agents/orchestrator.py` | Aggregates dual scores over a 500ms sliding window, queries local Qwen 2.5 via LangChain, enforces rule fallbacks, correlates attack campaigns, and manages incident lifecycles. | **Consumes:** `orchestrator_queue`<br/>**Produces:** `prevention_queue`, `healing_queue`, `logging_queue` |
| **ResponseAgent** | `backend/agents/response_agent.py` | Enforces nftables firewall rules (IP blocks, rate limits, device isolation), checks whitelist IPs, persists state to `state/active_rules.json`, sweeps expired rules, and restarts failing services. | **Consumes:** `prevention_queue`, `healing_queue`<br/>**Produces:** `logging_queue` |
| **ObservabilityAgent** | `backend/agents/observability_agent.py` | Consumes system log entries, dual-writes to PostgreSQL (`system_logs`) and `ids_system.log` (for Promtail/Loki), and computes MTTD/MTTR security compliance reports. | **Consumes:** `logging_queue` |

---

## Machine Learning Subsystem

### 17 Optimized Telemetry Features

The system extracts 17 continuous and discrete flow features optimized for real-time inference:

```
[packet_rate, byte_rate, flow_duration, dst_port, syn_flag_count, ack_flag_count,
 rst_flag_count, connection_errors, fwd_packets_per_second, bwd_packets_per_second,
 packet_length_mean, fwd_packet_length_mean, bwd_packet_length_mean,
 total_fwd_packets, total_bwd_packets, fwd_bytes, bwd_bytes]
```

*Supplemental features:* Shannon port entropy (`port_entropy` computed over a 100-packet sliding window), protocol encodings, and well-known IoT port flags (`1883`, `8883`, `5683`, `5684`, `502`, `47808`).

### Evaluation Metrics (CICIDS2017 Benchmark)

| Metric | LightGBM Classifier | Isolation Forest Anomaly |
|---|---|---|
| **Accuracy** | **99.35%** | 78.30% (unsupervised baseline) |
| **Precision** | **99.61%** | 53.95% (Average Precision) |
| **Recall** | **99.58%** | Optimal Threshold: -0.063 |
| **F1-Score** | **99.59%** | Contamination: 0.05 |
| **Inference Latency (p50)** | **< 0.5 ms** | **< 0.8 ms** |
| **Inference Latency (p99)** | **< 1.8 ms** | **< 2.5 ms** |

---

## Prerequisites & System Requirements

| Requirement | Minimum | Recommended | Notes |
|---|---|---|---|
| **Docker** | 24.0+ | Latest | Container runtime |
| **Docker Compose** | v2.20+ | Latest | Compose orchestration |
| **Python** | 3.11+ | 3.11 / 3.12 | For local non-Docker development |
| **Node.js** | 18.0+ | 20.0+ LTS | For frontend dashboard development |
| **RAM** | 8 GB | 16 GB | Required for Ollama + Loki + PostgreSQL |
| **CPU** | 4 Cores | 8 Cores | Multi-threaded model inference |
| **GPU (Optional)** | NVIDIA GTX 1660+ | RTX 3060+ / T4 | Accelerates local Ollama LLM reasoning |

---

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/your-username/autonomous_llm_multiagent_iot_ids_ips_repository.git
cd autonomous_llm_multiagent_iot_ids_ips_repository

# Copy example configuration
cp .env.example .env

# Generate a cryptographically secure JWT secret key
openssl rand -hex 32
# Paste output into JWT_SECRET_KEY in .env
```

### 2. Launch Entire Infrastructure via Docker Compose

```bash
docker compose up -d
```

*This launches 7 services:* PostgreSQL (`5433:5432`), FastAPI Backend (`8000:8000`), React Dashboard (`5173:80`), Loki (`3100:3100`), Promtail, Grafana (`3000:3000`), and Ollama (`11435:11434`).

### Capturing Ethernet and Wi-Fi Traffic

The Suricata and Zeek runners can capture one or more host interfaces. Pass the
actual interface names on the host where the tools run:

```bash
sudo bash traffic_capture/suricata_runner.sh eth0 wlan0
sudo bash traffic_capture/zeek_runner.sh eth0 wlan0
```

Alternatively, pass `SURICATA_INTERFACES="eth0 wlan0"` or
`ZEEK_INTERFACES="eth0 wlan0"` through the process environment. The runner
scripts do not load `.env` themselves; when using `sudo`, pass environment
variables through `sudo env`. With more than one interface, logs are
written under per-interface directories, for example
`logs/suricata/eth0/eve.json` and `logs/zeek/current/wlan0/conn.log`. Configure
the backend's `.env` with comma-separated paths for all selected interfaces:

```dotenv
SURICATA_LOG_PATHS=/app/logs/suricata/eth0/eve.json,/app/logs/suricata/wlan0/eve.json
ZEEK_LOG_PATHS=/app/logs/zeek/current/eth0/conn.log,/app/logs/zeek/current/wlan0/conn.log
```

Those `/app/logs` paths apply to Docker Compose, which mounts the repository's
`logs` directory there. For a local backend, use the corresponding paths on the
host. Replace `eth0` and `wlan0` with the actual interface names. The machine
running the capture tools must expose each interface and grant capture
permissions; Wi-Fi client traffic not directed to this machine may require a
monitor-mode adapter or gateway/mirror visibility.

Check interface names with `ip -br link`; the Wi-Fi adapter must be exposed to
the host where capture runs. Capturing other Wi-Fi clients' traffic may require
a monitor-mode-capable adapter or gateway/mirror visibility.

### 3. Verify System Health

```bash
# Check running containers
docker compose ps

# Check comprehensive health endpoint
curl http://localhost:8000/health

# Check readiness probe (DB + Loki)
curl http://localhost:8000/health/ready
```

### 4. Default Credentials

- **React Dashboard UI**: `admin` / `admin123` (seeded automatically on first startup)
- **Grafana Observability**: `admin` / `admin` (at `http://localhost:3000`)
- **PostgreSQL Database**: `idsuser` / `idspassword` (database: `idsdb`)

---

## Service Ports & Topology

| Service | Host Port | Container Port | Purpose / URL |
|---|---|---|---|
| **FastAPI Backend** | `8000` | `8000` | REST API, WebSockets, Swagger UI (`/docs`) |
| **React Dashboard** | `5173` | `80` | Production Web UI (`http://localhost:5173`) |
| **PostgreSQL** | `5433` | `5432` | Primary Relational Data Store (`idsdb`) |
| **Grafana** | `3000` | `3000` | Visual Log & Metric Dashboards (`http://localhost:3000`) |
| **Loki** | `3100` | `3100` | High-Performance Log Ingestion & Storage |
| **Promtail** | *N/A* | *N/A* | System Log File Shipper (Internal Container) |
| **Ollama** | `11435` | `11434` | Local LLM Server (Qwen 2.5 3B / 1.5B) |

---

## Environment Variable Configuration

Below is a reference of key configuration variables defined in `.env`:

```ini
# Core Configuration
DATABASE_URL=postgresql://idsuser:idspassword@localhost:5433/idsdb
JWT_SECRET_KEY=replace_with_64_character_hex_key
JWT_EXPIRE_MINUTES=60
ENVIRONMENT=development
LOG_LEVEL=INFO

# Machine Learning Artifacts
LGB_MODEL_PATH=models/lgb_model_optimized.joblib
IF_MODEL_PATH=models/if_model_optimized.joblib
SCALER_PATH=models/scaler_optimized.joblib

# LLM Orchestrator
OLLAMA_HOST=http://localhost:11435
OLLAMA_MODEL=qwen2.5-3b-iot-ids
LLM_TIMEOUT_SECONDS=5.0

# Firewall & Simulation
FIREWALL_MODE=simulation          # 'simulation' for dev, 'production' for real nftables
FIREWALL_BLOCK_TTL=3600
FIREWALL_RATE_LIMIT_TTL=1800

# Observability
LOKI_URL=http://localhost:3100
GRAFANA_URL=http://localhost:3000
APP_LOG_PATH=logs/ids_system.log

# Mock Traffic Injector (Optional Testing)
MOCK_DATA_ENABLED=false
MOCK_TRAFFIC_RATE=10
```

---

## Complete API & WebSocket Reference

All REST endpoints under `/api/v1` require JWT Bearer Authentication (`Authorization: Bearer <token>`).

### 1. Authentication (`/auth`)
- `POST /auth/token` — Exchange username/password for a JWT access token.
- `POST /auth/register` — Register a new user (`viewer`, `analyst`, or `admin`).
- `GET /auth/me` — Inspect the currently authenticated identity and role.

### 2. Security Alerts (`/api/v1/alerts`)
- `GET /api/v1/alerts` — Paginated attack events (`limit`, `offset`, `severity=medium|high|critical`).

### 3. Incident Management (`/api/v1/incidents`)
- `GET /api/v1/incidents` — Paginated incident records (`state=detected|analyzing|mitigating|resolved|closed`).
- `GET /api/v1/incidents/{incident_id}` — Incident details with all associated attack alerts and summary.
- `POST /api/v1/incidents/{incident_id}/acknowledge` — Transitions incident to `resolved` and records an audit log.

### 4. Device Inventory & Isolation (`/api/v1/devices`)
- `GET /api/v1/devices` — Monitored IoT inventory (`is_isolated=true|false`).
- `POST /api/v1/devices/{device_id}/isolate` — Manually isolates device, creates firewall block rule, logs audit event.
- `POST /api/v1/devices/{device_id}/release` — Releases device from isolation, flushes firewall rule, logs audit event.

### 5. Administrative Audit Logs (`/api/v1/audit-logs`)
- `GET /api/v1/audit-logs` — Admin-only audit log stream (`username`, `action`, `resource_type`, `start_time`, `end_time`).

### 6. Live Traffic & WebSocket Streaming
- `GET /api/v1/live-traffic` — Returns the latest 50 captured network flow records.
- `WebSocket /api/v1/ws/live-traffic` — Real-time bidirectional WebSocket pushing live flow batches, threat alerts, and 5-second metric snapshots.

### 7. Real-Time Metrics (`/api/v1/metrics`)
- `GET /api/v1/metrics` — JSON snapshot including queue depths, ML latency percentiles (p50/p95/p99), agent event throughput, network kbps/pps rates, packet drops, and active incident counts.

### 8. Dynamic Configuration (`/api/v1/config`)
- `GET /api/v1/config` — Retrieve current detection thresholds and IP whitelists.
- `PUT /api/v1/config` — Admin-only live update of thresholds (`composite_threshold`, `whitelist_ips`) propagated directly to running agents without restart.

### 9. Security Reports (`/api/v1/reports`)
- `GET /api/v1/reports` — List generated reports or trigger on-demand generation (`type=daily|weekly|monthly`).
- `GET /api/v1/reports/{report_id}` — Retrieve full report including MTTD and MTTR metrics (`format=json|csv`).

### 10. Health & Liveness Probes (`/health`)
- `GET /health` — Full component health status (PostgreSQL, ML models, Ollama, 5 agents, Loki, Grafana).
- `GET /health/ready` — Kubernetes/Docker readiness probe (status 200/503).
- `GET /health/live` — Kubernetes/Docker liveness probe.

---

## Role-Based Access Control (RBAC)

| Endpoint Group | Viewer | Analyst | Admin |
|---|:---:|:---:|:---:|
| Read Alerts, Incidents, Devices, Live Traffic, Metrics | ✅ | ✅ | ✅ |
| View Security Reports & Download CSV | ✅ | ✅ | ✅ |
| Acknowledge Incidents | ❌ | ✅ | ✅ |
| Isolate / Release IoT Devices | ❌ | ✅ | ✅ |
| Read System Configuration | ❌ | ✅ | ✅ |
| Update Detection Thresholds & IP Whitelists | ❌ | ❌ | ✅ |
| View Administrative Audit Logs | ❌ | ❌ | ✅ |

---

## Observability & Monitoring (Grafana + Loki)

The platform includes pre-provisioned Grafana dashboards pulling logs from Promtail/Loki:

1. **IDS System Logs**: Real-time log streams grouped by agent (`TrafficAgent`, `AnalysisAgent`, `LLMOrchestrator`, `ResponseAgent`, `ObservabilityAgent`) and log levels.
2. **IDS Attack Activity**: Visual timeline of attacks detected, classification distributions, and threat severity charts.
3. **IDS API Health**: Request latencies, error codes, WebSocket client count, and queue depths.
4. **IDS Firewall Mitigation**: Active nftables block rules, rate limits, device isolation statuses, and expiration timelines.
5. **IDS Infrastructure Metrics**: Host and container CPU, memory, disk, and network I/O stats.

Access Grafana at `http://localhost:3000` (User: `admin` / Pass: `admin`).

---

## Threat Simulation & Live Verification

The repository includes helper scripts to simulate attack traffic and test autonomous mitigation end-to-end:

### 1. Interactive Threat Injector
```bash
python scripts/inject_attack.py
```
*Injects synthetic DDoS, PortScan, or BruteForce flows into `logs/eve.json` targeting seeded IoT devices.*

### 2. Verify Device Isolation Status
```bash
python scripts/check_devices.py
```
*Queries PostgreSQL to verify if the attacked IoT device IP was automatically marked `is_isolated=True`.*

### 3. Bulk Un-Isolate Devices
```bash
python scripts/unisolate_devices.py
```
*Resets all isolated devices back to normal operating state and clears firewall rules.*

### 4. End-to-End Demo Simulation
```bash
python scripts/simulate_demo_attack.py
```
*Runs a multi-stage attack scenario demonstrating real-time detection, LLM reasoning, alert emission, and self-healing.*

---

## LLM Fine-Tuning & Model Management

The system supports fine-tuning small LLMs (e.g., `Qwen2.5-3B-Instruct` or `Qwen2.5-1.5B-Instruct`) specifically on IoT cybersecurity reasoning:

1. **Dataset Generator** (`scripts/generate_llm_dataset.py`): Creates instruction-tuning JSONL pairs covering diverse attack vectors and JSON mitigation recommendations.
2. **Kaggle / Colab Notebook** (`scripts/kaggle_qwen25_3b_finetune.ipynb`): Fine-tunes the model using LoRA / QLoRA with Unsloth in ~15 minutes on a free GPU.
3. **Model Importer** (`scripts/import_fine_tuned_model.ps1` / `scripts/import_fine_tuned_model.sh`): Converts GGUF weights into an Ollama model format and imports it automatically.

---

## Development & Local Testing

### Running Locally without Docker

```bash
# 1. Setup Virtual Environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Launch Supporting Services (DB + Loki)
docker compose up -d db loki promtail grafana

# 4. Run Migrations & Seed Default Data
alembic upgrade head
python scripts/create_admin.py
python scripts/seed_devices.py

# 5. Start Backend API
uvicorn backend.main:app --reload --port 8000

# 6. Start React Frontend Dashboard
cd dashboard
npm install
npm run dev
```

### Running Test Suite

```bash
# Run all unit, integration, and property-based tests
pytest tests/ -v

# Run with test coverage reporting
pytest tests/ --cov=backend --cov-report=term-missing
```

Each pytest run writes a separate execution log for every test case under `logs/test_cases/<run-id>/`.

---

## Troubleshooting & FAQs

### Q1: The API fails with `RuntimeError: JWT_SECRET_KEY environment variable must be set`
**Fix**: Ensure `.env` exists in the repository root and contains a non-empty `JWT_SECRET_KEY`. Generate one using `openssl rand -hex 32`.

### Q2: What happens if Ollama is slow or down?
**Fix**: The `LLMOrchestrator` enforces a 5-second async timeout. If Ollama fails or times out, the system automatically falls back to deterministic rule-based mitigation (`rule_based_fallback`), ensuring uninterrupted protection.

### Q3: Why is my device not blocking traffic on Windows?
**Fix**: On non-Linux environments, the firewall operates in `FIREWALL_MODE=simulation`, logging all block and rate-limit commands without executing Linux `nftables` commands. In Linux containers with `CAP_NET_ADMIN`, set `FIREWALL_MODE=production`.

### Q4: How do I access the Swagger interactive documentation?
**Fix**: Navigate to `http://localhost:8000/docs` in your browser while the backend is running.
