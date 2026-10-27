<<<<<<< HEAD
# Nexora — AI-Powered Security Monitoring & Incident Reconstruction

Nexora doesn't stop at "flag the outlier on a dashboard." It **correlates flagged
events across time into one coherent incident** — the mechanism that separates
UEBA-style tooling from plain anomaly detection — and shows the evidence chain
that produced each incident. Detection is validated with measured numbers, not
numbers the simulator guarantees.

This repo is a **complete, runnable system**: a simulator, a detection engine, a
correlation engine, a FastAPI backend (REST + WebSocket, Postgres/SQLite), and a
React dashboard wired to live data.

![pipeline](https://img.shields.io/badge/pipeline-simulator→detection→correlation→API→UI-blue)

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│  FRONTEND  (React + TS, frontend/)                            │
│  Dashboard · live stream · correlation graph · incidents ·    │
│  evidence chain · benchmarks — one WebSocket, REST snapshots  │
└───────────────▲───────────────────────────────────────────────┘
                │ REST + WebSocket
┌───────────────┴───────────────────────────────────────────────┐
│  BACKEND  (FastAPI, backend/)                                 │
│  /api/events /api/incidents /api/metrics /api/simulate/...    │
│  /ws/events  ·  SQLAlchemy → Postgres (or SQLite)             │
│                                                               │
│  LIVE PIPELINE (backend/app/pipeline.py), every tick:         │
│    simulator ─▶ rolling window ─▶ detection ─▶ correlation ─▶ │
│    persist + broadcast                                        │
└───┬─────────────────┬────────────────────┬────────────────────┘
    │                 │                    │
┌───▼──────────┐ ┌────▼──────────┐ ┌───────▼────────────────────┐
│ simulator/   │ │ detection/    │ │ correlation/                │
│ normal traffic│ │ IsolationForest│ │ entity-linked event graph   │
│ + 4 attack    │ │ + rule flags  │ │ + attack-chain templates    │
│ injectors     │ │ + classifier  │ │ + severity scoring          │
│ (p2-pipeline) │ │               │ │ → incident + evidence chain │
└───────────────┘ └───────────────┘ └─────────────────────────────┘
```

Single canonical event schema (`p2-pipeline/schema/event_schema.json`) is the
one contract: the backend Pydantic models and the frontend TypeScript types
mirror it, and a test asserts they stay in sync.

---

## Quick start

### Option A — Docker + Postgres (primary)

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD to a long random alphanumeric password in .env.
docker compose up --build
# open http://localhost:8000
```

One image builds the frontend, installs the backend, trains the detection models,
and serves the SPA + API + WebSocket on port 8000, backed by Postgres (events and
incidents persist across restarts).

### Option B — Local (no Docker, SQLite)

```bash
# 1. Python backend (from repo root)
python -m pip install -r requirements.txt
python -m detection.train_baseline        # one-time: trains models + writes metrics
python -m uvicorn backend.app.main:app --port 8000
#    → http://localhost:8000 (serves the SPA if frontend/dist exists)

# 2. Frontend dev server (separate terminal, optional — for hot reload)
cd frontend
npm install
npm run dev                                 # → http://localhost:5173 (auto-targets :8000)
```

- `http://localhost:8000/docs` — interactive API docs
- `ws://localhost:8000/ws/events` — live event/incident/stats stream

---

## Using it

Open the dashboard, click **Inject Attack**, and pick one of the four scoped
attacks. Watch it stream into the live feed, get flagged by the detector,
reconstructed by the correlation engine into a single incident, and display the
actual evidence chain on the graph; select a node for its description. The **Incidents** page shows the
full evidence chain; **Analytics** shows the benchmark numbers.

---

## Attack scenarios (scope — plan §5/§7)

| Attack | Signal class | How it's detected | Correlation template |
|---|---|---|---|
| **Brute force** | auth | ≥5 failed logins/user in a window → compromise chain | failures → success → db read → file download |
| **Port scan** | network | ≥15 `connection_attempt`/IP in a window | burst of probes, one source IP |
| **Data exfiltration** | volume | large file download (≥10 MB) | login → db read → bulk download |
| **API abuse** | rate | ≥25 `api_call`/IP in a window | API-call burst, one source IP |

Out of scope by design: privilege-escalation / insider scenarios, SQL-injection,
a learned graph-neural correlation model, enterprise streaming infra.

---

## Data strategy & metrics (plan §4, §10 — the honest framing)

Analytics prefers `data/processed/metrics_real.json` when present and otherwise
explicitly labels the simulated evaluation. The uploaded CICIDS2017 evaluation
uses a reproducible random sample and separate 50/20/30 training/validation/test
splits. IsolationForest fits benign training flows; preprocessing and threshold
are selected using labelled validation flows with a 5% benign false-positive
budget. Its model uses network-flow features;
it is a separate offline benchmark, not the live simulator detector.

The current measured result is classifier macro F1 **0.8817**, accuracy **0.9975**;
its binary attack precision/recall/F1 are **0.9957 / 0.9926 / 0.9942**.
IsolationForest precision **0.6885**, recall **0.4504**, F1 **0.5445**, benign
false-positive rate **0.0498**. This improves anomaly recall from **0.0856** at
the previous conservative threshold, at the cost of more false positives.
It still misses attacks; the stronger supervised result is reported separately.
Rare classes may be absent from this sample; row splits do not establish
performance on future days or different organisations.

Correlation is a separate deterministic self-check on four simulated scenarios.
It is not real-dataset correlation accuracy. Runtime processing time measures
detection, correlation and storage; it excludes attack scheduling, WebSocket
transport and browser rendering.

For the **real-data** number (CICIDS2017 / UNSW-NB15), drop CSVs directly into
`data/raw/` or its subdirectories and run:

```bash
python -m detection.benchmark_cicids --dataset cicids2017   # or --dataset unsw
```

This writes `data/processed/metrics_real.json`. The live demo runs on the
simulator because no public dataset gives cross-system (auth→api→db→file) event
correlation at the granularity the reconstruction engine needs.

---

## Project structure

```
p2-pipeline/simulator/    normal-traffic generator + 4 attack injectors
p2-pipeline/schema/       canonical event schema (single source of truth)
detection/                features, IsolationForest detector, classifier, training, benchmark
correlation/              event graph, templates, matcher, scoring, engine
backend/app/              FastAPI app, routers, live pipeline, WebSocket, DB models
frontend/src/             React dashboard (pages, live WebSocket provider, graph)
data/processed/           generated metrics (+ class distributions)
```

## Testing

```bash
# simulator schema tests
cd p2-pipeline && python -m pytest tests/ -v
# correlation / detection sanity (from repo root)
python -m pytest tests p2-pipeline/tests -q -p no:cacheprovider
npm run lint --prefix frontend
npm run build --prefix frontend
node tests/test_event_display.mjs
```

## Tech stack

Python · FastAPI · scikit-learn · NetworkX · SQLAlchemy · Postgres/SQLite ·
React + TypeScript · Vite · Tailwind · Framer Motion · WebSocket.

## Deployment scope

This is a functioning security-monitoring **simulation**, not a production log
collector. Events are generated continuously at runtime (default: one normal
event about every three seconds); injected attacks are scheduled over six
seconds. Uploaded CSVs supply offline evaluation, not live events. Recommended
responses are guidance, not actions that block accounts or prevent attacks.

Docker serves the built frontend, API and WebSocket together, uses a non-root
application user, checks `/api/health`, and persists Postgres data. Raw CSVs and
`.env` files are excluded from the image; the aggregate real benchmark is
included. Re-run the benchmark before building when the dataset changes.

Run **one Uvicorn worker and one app instance**: the simulator and broadcasting
state are in memory. Compose binds port 8000 to localhost. For remote access,
put an authenticated TLS reverse proxy in front of the app and permit WebSocket
upgrades; authentication is not implemented in this project. Configure
`CORS_ORIGINS` to the deployed frontend origin. Do not expose the simulation API
as an unrestricted public service. Event storage and historical ID sets grow
with runtime, so arrange retention for long-running deployments.

Local built-frontend launch: `npm ci --prefix frontend`,
`npm run build --prefix frontend`, then
`python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`.
See [AUDIT.md](AUDIT.md) for verification results and remaining limits.
=======
# Nexora
>>>>>>> 6d1ab720f25bbd1e730baf01d4389aaf815f264b
