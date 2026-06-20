# Cloud-based DDoS Attack Detection System

**Ensemble Machine Learning + Containerized Deployment**

A complete, end-to-end system that detects Distributed Denial-of-Service
(DDoS) attacks using an **XGBoost + Random Forest** ensemble, trained on the
**BCCC-cPacket-Cloud-DDoS-2024** dataset. The system provides real-time
detection via a REST API, a live monitoring dashboard, a safe traffic-replay
simulator, and a one-command Docker deployment.

> **Defensive security project.** This system *detects* attacks. It contains
> no attack tooling. The "simulation" component replays *already-labeled*
> flows from the public dataset against the detector — it never generates
> real network traffic.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Project Structure](#2-project-structure)
3. [How It Works](#3-how-it-works)
4. [Quick Start (Local)](#4-quick-start-local)
5. [Quick Start (Docker)](#5-quick-start-docker)
6. [The Machine Learning Pipeline](#6-the-machine-learning-pipeline)
7. [The API Server](#7-the-api-server)
8. [The Dashboard](#8-the-dashboard)
9. [The Traffic Simulator](#9-the-traffic-simulator)
10. [Configuration](#10-configuration)
11. [Cloud Deployment Guide](#11-cloud-deployment-guide)
12. [Testing](#12-testing)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. System Architecture

The system is a **hybrid offline/online design**.

```
                          CLOUD VM (Oracle Cloud / AWS EC2)
   ┌──────────────────────────────────────────────────────────────┐
   │                  Docker Compose network                      │
   │                                                                │
   │   ┌──────────────────┐  HTTP/REST  ┌────────────────────────┐ │
   │   │  api_server      │◄────────────┤  dashboard             │ │
   │   │  FastAPI  :8000  │             │  Streamlit  :8501      │ │
   │   │                  │             │                        │ │
   │   │  /predict        │             │  live detection feed   │ │
   │   │  /predict/batch  │             │  confidence timeline   │ │
   │   │  /health         │             │  attack/normal charts  │ │
   │   │  /metrics        │             │  alert table           │ │
   │   └────────┬─────────┘             └────────────────────────┘ │
   │            │ loads model                                       │
   │            ▼                        ┌────────────────────────┐ │
   │   ┌──────────────────┐              │  simulation            │ │
   │   │  models/         │◄─────────────┤  traffic replayer      │ │
   │   │  ddos_model.pkl  │   trains     │  replays dataset rows  │ │
   │   │  (shared volume) │              │  → POST /predict       │ │
   │   └────────▲─────────┘              └────────────────────────┘ │
   └────────────┼───────────────────────────────────────────────────┘
                │
        ┌───────┴────────────┐   OFFLINE — run once / on a retrain schedule
        │  ml_training       │
        │  XGBoost + RF      │   loads BCCC-cPacket-Cloud-DDoS-2024,
        │  → ddos_model.pkl  │   trains, evaluates, writes the artifact
        └────────────────────┘
```

**Why this split?**

- **Training is a batch job.** It is resource-heavy and runs rarely, so it is
  decoupled from inference. It consumes the full dataset and emits one
  versioned artifact (`models/ddos_model.pkl`).
- **The API is stateless per request.** It loads the model once at startup
  into memory. Because each prediction is independent, the API can be
  replicated behind a load balancer for horizontal scaling.
- **The dashboard holds no ML logic.** It is a pure consumer of the API's
  `/health` and `/metrics` endpoints — clean separation of concerns.
- **The simulator is the safe demonstration path.** It replays labeled flows
  from the dataset as timed HTTP requests, which is the standard academic way
  to demonstrate a real-time IDS without generating real attack traffic.
- **The shared model volume** is the only coupling point between the offline
  and online tiers. In a larger production system this becomes an object
  store (S3 / OCI Object Storage); a Docker volume is the thesis-appropriate
  equivalent.

---

## 2. Project Structure

```
project/
├── ml_training/              # OFFLINE: the training pipeline
│   ├── data_loader.py        #   loads + cleans BCCC CSV(s)
│   ├── feature_engineering.py#   raw flows → engineered feature matrix
│   ├── model.py              #   XGBoost + Random Forest ensemble
│   ├── evaluator.py          #   hold-out metrics, CV, ROC/PR
│   ├── visualizer.py         #   the multi-panel research figure
│   └── train.py              #   entrypoint: ties the pipeline together
│
├── api_server/               # ONLINE: the inference service
│   ├── app.py                #   FastAPI app + endpoints
│   └── metrics.py            #   thread-safe rolling operational metrics
│
├── dashboard/                # ONLINE: the monitoring UI
│   └── app.py                #   Streamlit dashboard (polls the API)
│
├── simulation/               # the safe traffic-replay demonstrator
│   └── replayer.py           #   replays labeled dataset rows → API
│
├── utils/                    # shared across every module
│   ├── config.py             #   centralized configuration
│   ├── logger.py             #   centralized logging
│   └── schemas.py            #   Pydantic request/response contracts
│
├── docker/                   # containerization
│   ├── Dockerfile.api
│   ├── Dockerfile.dashboard
│   ├── Dockerfile.simulation
│   └── docker-compose.yml
│
├── tests/                    # unit + smoke tests
│   ├── test_ml_pipeline.py
│   └── make_synthetic.py     #   generates a synthetic dataset for testing
│
├── models/                   # trained artifacts land here (git-ignored)
├── data/                     # place the dataset here (git-ignored)
├── logs/                     # rotating log files (git-ignored)
├── ddos_results/             # research figure + report (git-ignored)
│
├── config.yaml               # optional configuration overrides
├── .env.example              # environment-variable template
├── Makefile                  # single-command operations
├── requirements-*.txt        # per-service dependency files
└── README.md
```

---

## 3. How It Works

**End-to-end data flow:**

1. **Load.** `DatasetLoader` reads the BCCC CSV(s), normalizes column names,
   coerces every numeric column, and locates the `label` column.
2. **Engineer.** `FeatureEngineer` adds ~18 attack-aware derived features —
   TCP-flag ratios (flag floods), packet-size dispersion (amplification),
   inter-arrival-time statistics (Slowloris/Slow-Read), and packet/byte rates
   (volumetric floods).
3. **Train.** `EnsembleDDoSModel` fits a Random Forest and an XGBoost
   classifier. Both handle class imbalance natively: RF via
   `class_weight="balanced"`, XGBoost via `scale_pos_weight`. The final verdict
   is a weighted soft-vote of the two probabilities.
4. **Evaluate.** `Evaluator` produces hold-out accuracy/F1/precision/recall/AUC
   per model, a 5-fold cross-validation score, ROC and PR curves, the confusion
   matrix, and an ensemble-averaged feature-importance ranking.
5. **Persist.** The whole model — both sub-models plus the frozen feature list
   — is saved as a single `joblib` artifact.
6. **Serve.** The FastAPI server loads that artifact once and exposes
   `/predict`. Inference latency is ~25–35 ms per flow.
7. **Demonstrate.** The simulator replays labeled dataset rows to the API on a
   scripted timeline (alternating benign and attack phases). The dashboard
   polls `/metrics` and visualizes the live detection stream.

---

## 4. Quick Start (Local)

**Requirements:** Python 3.11+, ~2 GB RAM.

```bash
# 1. install dependencies
make install            # or: pip install -r requirements-*.txt

# 2. place the dataset
#    put BCCC-cPacket-Cloud-DDoS-2024 (CSV or folder of CSVs) in data/
#    e.g.  data/BCCC-cPacket-Cloud-DDoS-2024/

# 3. train the model
make train DATA=data/BCCC-cPacket-Cloud-DDoS-2024
#    → produces models/ddos_model.pkl
#               ddos_results/classification_report.txt
#               ddos_results/ddos_research_results.png

# 4. start the API server   (terminal 1)
make api                #  http://localhost:8000/docs

# 5. start the dashboard    (terminal 2)
make dashboard          #  http://localhost:8501

# 6. replay traffic         (terminal 3)
make simulate DATA=data/BCCC-cPacket-Cloud-DDoS-2024
```

**No dataset yet?** Smoke-test the whole pipeline with synthetic data:

```bash
make synthetic                       # writes data/synthetic_test.csv
make train DATA=data/synthetic_test.csv
make test                            # run the unit suite
```

---

## 5. Quick Start (Docker)

**Requirements:** Docker + Docker Compose v2.

```bash
# 1. train the model first (the API container loads this artifact)
make train DATA=data/BCCC-cPacket-Cloud-DDoS-2024
#    — or train inside a container if you prefer; the artifact just
#      needs to exist in ./models before `make up`

# 2. build + start API and dashboard with ONE command
make up
#    → API       http://localhost:8000/docs
#    → Dashboard http://localhost:8501

# 3. (optional) replay traffic as a one-off container
make sim-docker

# 4. stop everything
make down
```

Behind `make up` is simply:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

---

## 6. The Machine Learning Pipeline

### Model

| Sub-model         | Role                          | Imbalance handling          |
|-------------------|-------------------------------|-----------------------------|
| Random Forest     | robust, low-variance baseline | `class_weight="balanced"`   |
| XGBoost           | high-accuracy gradient boost  | `scale_pos_weight = N⁻/N⁺`  |
| **Ensemble**      | weighted soft-vote (0.5/0.5)  | inherits both               |

The blend weights and decision threshold are configurable
(`config.yaml → model`).

### Engineered features

Beyond the raw dataset columns, the following derived features are computed
because each targets a specific DDoS family:

- **Flow balance** — `bytes_ratio`, `pkt_ratio`: volumetric floods skew the
  forward/backward direction heavily.
- **TCP flag ratios** — `syn_ack_ratio`, `syn_fin_ratio`, `rst_pkt_ratio`,
  `flag_total`, `flag_density`: SYN/ACK/RST/FIN floods are dominated by control
  packets.
- **Packet-size dispersion** — `pkt_len_range`, `pkt_len_cv`: amplification
  attacks produce large, uniform packets.
- **Inter-arrival timing** — `iat_range`, `iat_cv`: low-and-slow attacks
  (Slowloris, Slow-Read) have long, irregular gaps.
- **Rates** — `pkt_rate`, `byte_rate`: volumetric floods push these very high;
  slow attacks push them very low.

> **Note on scaling.** Tree-based models are invariant to monotonic feature
> scaling, so no `StandardScaler` is applied to the ensemble — it would be
> wasted computation. This is a deliberate, justified design choice.

### Outputs

After `make train` you get:

- `models/ddos_model.pkl` — the deployable artifact
- `ddos_results/classification_report.txt` — precision/recall/F1 + CV score
- `ddos_results/ddos_research_results.png` — a 9-panel research figure
  (class distribution, model comparison, confusion matrix, ROC, PR,
  feature importance, real-time timeline, detection-statistics pie, alert log)

---

## 7. The API Server

FastAPI, served by Uvicorn on port **8000**.

| Method | Endpoint          | Purpose                                       |
|--------|-------------------|-----------------------------------------------|
| GET    | `/health`         | Liveness + model status (Docker healthcheck)  |
| POST   | `/predict`        | Score one flow                                |
| POST   | `/predict/batch`  | Score many flows in one call (higher throughput) |
| GET    | `/metrics`        | Rolling operational metrics (dashboard polls) |
| GET    | `/docs`           | Interactive Swagger UI                        |

**Example request:**

```bash
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "total_packets": 5000, "total_bytes": 250000,
      "syn_flag_count": 4800, "ack_flag_count": 10,
      "flow_duration": 0.5, "fwd_bytes": 240000, "bwd_bytes": 1000
    },
    "flow_id": "demo-1",
    "true_label": "DDoS-SYN-Flood"
  }'
```

**Example response:**

```json
{
  "flow_id": "demo-1", "is_ddos": true, "confidence": 0.9949,
  "rf_score": 0.9899, "xgb_score": 0.9998, "is_alert": true,
  "threshold": 0.5, "latency_ms": 28.4
}
```

The optional `true_label` field is used **only** for live-accuracy metrics
during simulation — it is never used in the prediction itself. Any feature the
model expects but the request omits is zero-filled server-side, so the API is
resilient to minor schema drift. (For accurate scoring, send a *complete*
flow record — the simulator does this automatically.)

---

## 8. The Dashboard

Streamlit, port **8501**. It is a thin presentation layer — it polls the API
and visualizes the results. Panels:

- **System status** — API health, model loaded, feature count, uptime
- **Live metrics** — total analyzed, DDoS detected, benign, alerts, latency
- **Detection-rate timeline** and **average-confidence timeline**
- **Live detection quality** — accuracy + the TP/FP/TN/FN confusion counts
  (populated once labeled flows are scored — the simulator sends these)
- **Manual flow tester** — a quick what-if tool (with a clear caveat that
  partial input is unreliable)
- **Auto-refresh** toggle

---

## 9. The Traffic Simulator

`simulation/replayer.py` replays labeled dataset rows to the API on a scripted
timeline of alternating benign and attack scenarios (SYN Flood, UDP Flood,
HTTP Flood, DNS/NTP Amplification, Slowloris, ICMP Flood). It:

1. pre-flight-checks that the API is up and has a model loaded,
2. samples dataset rows matching the current scenario,
3. POSTs them to `/predict` at a configurable rate,
4. prints a running accuracy summary and writes alerts.

```bash
python -m simulation.replayer \
  --data data/BCCC-cPacket-Cloud-DDoS-2024 \
  --sample 0.1 --duration 120 --speed 15
```

The first scenario is 20 s of benign traffic, so a run shorter than ~25 s will
only ever see benign flows — use `--duration 120` (the default) for a full
demo that crosses every attack phase.

---

## 10. Configuration

Three layers, in increasing precedence:

```
dataclass defaults  <  config.yaml  <  environment variables
```

- **`utils/config.py`** — the coded defaults (also the single source of truth
  for the dataset's label taxonomy).
- **`config.yaml`** — edit this for experiments (sample fraction,
  hyperparameters, blend weights, thresholds).
- **Environment variables** — `DDOS_*` variables; ideal for Docker. Copy
  `.env.example` to `.env` and adjust. Docker Compose reads `.env`
  automatically.

Common knobs:

| Variable                | Meaning                              | Default |
|-------------------------|--------------------------------------|---------|
| `DDOS_DATASET_PATH`     | Path to the dataset CSV / folder     | `data/BCCC-cPacket-Cloud-DDoS-2024` |
| `DDOS_SAMPLE_FRAC`      | Fraction of the dataset to train on  | `1.0`   |
| `DDOS_ALERT_THRESHOLD`  | Confidence at which an alert fires   | `0.75`  |
| `DDOS_API_URL`          | Where the simulator/dashboard reach the API | `http://localhost:8000` |
| `DDOS_SIM_SPEED`        | Replay rate, flows/second            | `15`    |
| `DDOS_LOG_LEVEL`        | `DEBUG` / `INFO` / `WARNING`         | `INFO`  |

---

## 11. Cloud Deployment Guide

The system is designed to run on a single small cloud VM. Below are
step-by-step instructions for **Oracle Cloud** (the Always-Free tier is
sufficient) and **AWS EC2**. The steps are nearly identical because both end
up running the same Docker Compose stack.

### 11.A — Oracle Cloud Infrastructure (OCI)

**1. Create the VM**

- OCI Console → *Compute → Instances → Create Instance*
- Image: **Canonical Ubuntu 22.04**
- Shape: **VM.Standard.A1.Flex** (Always-Free: up to 4 OCPU / 24 GB RAM) or
  **VM.Standard.E2.1.Micro**
- Add your SSH public key, then *Create*.

**2. Open the firewall ports**

In the instance's **VCN → Security List**, add two ingress rules:

| Source CIDR | Protocol | Destination Port | Purpose   |
|-------------|----------|------------------|-----------|
| `0.0.0.0/0` | TCP      | `8000`           | API       |
| `0.0.0.0/0` | TCP      | `8501`           | Dashboard |

> For a real deployment, restrict the source CIDR to your own IP.

**3. SSH in and install Docker**

```bash
ssh ubuntu@<YOUR_VM_PUBLIC_IP>

sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y docker.io docker-compose-plugin git make
sudo usermod -aG docker $USER
# log out and back in so the group change takes effect
exit
ssh ubuntu@<YOUR_VM_PUBLIC_IP>
```

Ubuntu's host firewall also needs the ports opened:

```bash
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 8501 -j ACCEPT
sudo netfilter-persistent save
```

**4. Deploy the project**

```bash
# copy the project to the VM — either git clone, or scp from your laptop:
scp -r project ubuntu@<YOUR_VM_PUBLIC_IP>:~/project
ssh ubuntu@<YOUR_VM_PUBLIC_IP>
cd ~/project

# upload the dataset into data/ (scp it, or download it on the VM)

# train the model on the VM
pip install -r requirements-train.txt
python3 -m ml_training.train --data data/BCCC-cPacket-Cloud-DDoS-2024

# bring up the containerized stack
make up
```

**5. Access it**

- API docs:  `http://<YOUR_VM_PUBLIC_IP>:8000/docs`
- Dashboard: `http://<YOUR_VM_PUBLIC_IP>:8501`

**6. Run the live demo**

```bash
make sim-docker      # replays traffic; watch the dashboard update live
```

### 11.B — AWS EC2

**1. Launch the instance**

- EC2 Console → *Launch Instance*
- AMI: **Ubuntu Server 22.04 LTS**
- Type: **t2.medium** (or **t3.small** for a lighter setup)
- Key pair: create or select one for SSH.

**2. Security Group**

Add two inbound rules:

| Type       | Port | Source    |
|------------|------|-----------|
| Custom TCP | 8000 | 0.0.0.0/0 |
| Custom TCP | 8501 | 0.0.0.0/0 |

**3. Install Docker** — identical to OCI step 3 above (AWS does not need the
extra `iptables` step; the Security Group is sufficient).

```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git make
sudo usermod -aG docker $USER
exit && ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

**4. Deploy** — identical to OCI step 4:

```bash
scp -i your-key.pem -r project ubuntu@<EC2_PUBLIC_IP>:~/project
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
cd ~/project
pip install -r requirements-train.txt
python3 -m ml_training.train --data data/BCCC-cPacket-Cloud-DDoS-2024
make up
```

**5. Access** — `http://<EC2_PUBLIC_IP>:8000/docs` and `:8501`.

### 11.C — Keeping it running

`docker-compose.yml` sets `restart: unless-stopped`, so the containers come
back automatically after a VM reboot. To update after a code change:

```bash
cd ~/project
git pull            # or re-scp
make rebuild        # clean rebuild
make up
```

### 11.D — Production hardening (beyond thesis scope, worth mentioning)

- Put an Nginx reverse proxy in front and terminate **HTTPS** with
  Let's Encrypt.
- Restrict Security Group / Security List source CIDRs to known IPs.
- Move the model artifact to **object storage** (S3 / OCI Object Storage)
  instead of a bind-mount.
- Add **Prometheus + Grafana** by scraping the `/metrics` endpoint.

---

## 12. Testing

```bash
make test           # runs pytest over tests/
```

The suite covers: binary-label mapping, feature-engineering robustness
(column freezing, zero-fill of missing features, no infinities from
division-based features), model train/predict, the save/load roundtrip
(reloaded model must give identical predictions), and batch-vs-single
consistency.

For a full integration smoke test without the real dataset:

```bash
make synthetic
make train DATA=data/synthetic_test.csv
make api &                                  # background
python -m simulation.replayer --data data/synthetic_test.csv \
  --sample 0.3 --duration 60 --speed 25
```

---

## 13. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| API `/health` returns `"degraded"` | No model artifact. Run `make train` first; it must produce `models/ddos_model.pkl`. |
| `ImportError: xgboost` | `pip install xgboost`. In Docker, `libgomp1` is already installed by the Dockerfile. |
| Dashboard says "Cannot reach the detection API" | The API container isn't up, or `DDOS_API_URL` is wrong. Inside Docker it must be `http://api_server:8000`, not `localhost`. |
| Simulator only ever shows benign flows | Run too short. The first scenario is 20 s of benign traffic — use `--duration 120`. |
| Manual tester gives a weird verdict | Expected — it sends only a few features and the rest are zero-filled. Use the simulator for accurate scoring. |
| Ports 8000 / 8501 unreachable on the cloud VM | Firewall. Open them in the Security List (OCI) or Security Group (AWS); on OCI also open them in the host `iptables`. |
| `make: command not found` | Install `make`, or run the underlying commands directly (see each `make` target in the `Makefile`). |

---

## Academic Integrity Note

This is a **defensive cybersecurity research system**. It detects and
classifies attacks from a pre-existing, publicly available labeled dataset.
It does not contain, and must not be used to build, any tooling that
generates real attack traffic.
