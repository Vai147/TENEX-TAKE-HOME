# Tenex — ZScaler Log Analysis Console

A full-stack security console that ingests ZScaler web-proxy logs, flags anomalous
traffic with a deterministic detection engine, maps findings to the **MITRE ATT&CK**
kill chain, enriches destinations with **VirusTotal** threat intel, and narrates the
incident with **Claude**.

Upload a CSV → get ranked findings, a severity breakdown, a kill-chain coverage board,
threat-intel verdicts, exportable SIEM alerts, and a natural-language timeline you can
ask questions about.

---

## Features

- **Deterministic anomaly engine** — pure, testable detectors (no LLM in the detection
  path), each producing findings with a confidence score and severity band.
- **MITRE ATT&CK mapping** — findings roll up to techniques across all 14 tactics.
  Observed techniques light up; unobserved tactics stay empty, so the board doubles as
  an honest visibility-gap map rather than a checkbox overlay.
- **VirusTotal enrichment** — on-demand destination reputation lookups (rate-limited to
  the free public tier), cached, with a hard per-run cap so one upload can't drain the
  daily quota.
- **SIEM alert export** — findings serialize to an alert format for downstream tooling.
- **ATT&CK Navigator layer export** — technique coverage exports as a Navigator layer.
- **Claude narrative + chat** — an LLM layer summarizes the incident and answers
  follow-up questions grounded in the parsed data. The deterministic verdict and
  Claude's opinion are kept as **separate** fields.
- **Server-side entry search** — filter parsed log rows by action/status, user, source
  IP, or URL, with the query held in the URL.
- **Auth** — JWT login over a seeded prototype user.
- **Light/dark theme** — WCAG AA contrast in both.

---

## Architecture

```
┌─────────────┐        ┌──────────────────────────┐       ┌────────────┐
│  Next.js    │  HTTP  │        FastAPI           │  SQL  │ PostgreSQL │
│  frontend   │ ─────▶ │  parse → detect → enrich │ ─────▶│            │
│ (App Router)│ ◀───── │  → ATT&CK map → LLM      │       └────────────┘
└─────────────┘  JSON  └──────────────────────────┘
                              │            │
                       VirusTotal      Anthropic
                       (threat intel)  (narrative/chat)
```

The pipeline is a straight line: **parse** the CSV → run **detectors** → **enrich**
flagged destinations → **map** findings to ATT&CK → hand aggregates + findings to the
**LLM** for narration. Detection is fully deterministic; the LLM only explains, never
decides severity.

---

## Detection approach

**Anomaly detection is deterministic, not model-based — by design.** No LLM or ML
model sits in the detection path. Anomalies come from a set of pure statistical
detectors, each a `(entries) -> list[Finding]` function that scores a specific signal:

- **Statistical outliers** — `byte_volume` flags upload spikes with a **Tukey fence**
  (values beyond `Q3 + k·IQR`), so "abnormal" is defined relative to *this file's* own
  baseline rather than a hardcoded number.
- **Rate / burst thresholds** — `ip_burst`, `blocked_spike`, `host_sweep` score
  request velocity and fan-out over short windows.
- **Rarity scoring** — `rare_user_agent` weights how uncommon / signature-like a
  user-agent is.
- **Heuristic signals** — `tool_download`, `cloud_upload`, `off_hours` match known
  risky patterns.

Each finding carries a **confidence score** (0–1, clamped) derived from the signal's
strength, and a **severity band** derived from that confidence.

**Why deterministic over an ML/LLM detector:**

1. **Auditable** — every finding shows its evidence and math; an analyst can defend it.
2. **Reproducible** — same log in, same findings out, every run.
3. **No hallucinated alerts** — an LLM asked to *find* threats would invent or miss
   them; here that failure mode is structurally impossible.
4. **Testable** — pure functions get real unit tests (`cd backend && pytest`).

**Where the AI model fits:** Claude (`claude-haiku-4-5` by default; `claude-sonnet-5`
in production) is used **only to explain** the deterministic findings — it writes the
incident narrative and answers follow-up questions, grounded in the parsed data via a
forced tool-call schema. It never detects, ranks, or sets severity. The deterministic
verdict and Claude's opinion are stored as **separate fields**. See [`backend/app/llm.py`](backend/app/llm.py).

---

## Tech stack

| Layer     | Choice                                                            |
|-----------|-------------------------------------------------------------------|
| Frontend  | Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS v4, shadcn/ui, Recharts, next-themes |
| Backend   | FastAPI, SQLAlchemy 2, Pydantic v2, python-jose (JWT), passlib/bcrypt |
| Database  | PostgreSQL 16                                                     |
| AI        | Anthropic Claude (`claude-haiku-4-5` by default)                  |
| Intel     | VirusTotal API v3                                                 |
| Runtime   | Python 3.12, Docker Compose                                       |

---

## Detectors

Each detector is a pure `(entries) -> list[Finding]` function in
[`backend/app/detectors/`](backend/app/detectors/):

| Detector          | Signal                                            | Example ATT&CK mapping        |
|-------------------|---------------------------------------------------|-------------------------------|
| `ip_burst`        | Request bursts from a single source IP            | Credential Access · T1110     |
| `blocked_spike`   | Spike in blocked requests                         | Reconnaissance · T1595        |
| `rare_user_agent` | Uncommon / suspicious user-agent strings          | Initial Access · T1190        |
| `byte_volume`     | Outlier upload volume (Tukey fence)               | Exfiltration · T1048          |
| `host_sweep`      | Scripted client rapidly contacts distinct hosts   | Discovery · T1046             |
| `tool_download`   | Executable/script payload download                 | Command & Control · T1105     |
| `cloud_upload`    | Large upload to a known cloud service              | Exfiltration · T1567          |
| `off_hours`       | Traffic outside business hours                    | (behavioral signal)           |

The finding→technique mapping lives in [`backend/app/attack.py`](backend/app/attack.py).

---


## Quick start (Docker)

Requires Docker Desktop.

```bash
# from repo root
export ANTHROPIC_API_KEY=sk-ant-...        # optional: enables narrative/chat
export VIRUSTOTAL_API_KEY=...              # optional: enables threat intel
docker compose up --build
```


**Login:** `analyst` / `password123` (seeded on first boot — override with
`SEED_PASSWORD`).

Try the sample logs in [`examples/`](examples/):
`zscaler_anomalous.csv`, `zscaler_clean.csv`, `zscaler_vt_flagged.csv`.

---

## Local development (without Docker)

**Backend**
```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=sqlite:///./tenex_local.db   # or a local Postgres URL
uvicorn app.main:app --reload --port 8000
```

**Frontend**
```bash
cd frontend
npm install
echo 'NEXT_PUBLIC_API_BASE=http://localhost:8000' > .env.local
npm run dev
```

**Tests**
```bash
cd backend && pytest
```

---

## API

All routes are under `/api` and require a Bearer token except login.

| Method | Path                              | Description                          |
|--------|-----------------------------------|--------------------------------------|
| POST   | `/api/auth/login`                 | Exchange credentials for a JWT       |
| GET    | `/api/auth/me`                    | Current user                         |
| POST   | `/api/uploads`                    | Upload a ZScaler CSV                 |
| GET    | `/api/uploads`                    | List uploads                         |
| GET    | `/api/uploads/{id}`               | Parsed entries (paginated, `?q=` search) |
| GET    | `/api/uploads/{id}/anomalies`     | Findings, timeline, top talkers, narrative |
| POST   | `/api/uploads/{id}/enrich`        | Run VirusTotal enrichment            |
| GET    | `/api/uploads/{id}/threat-intel`  | Enrichment results                   |
| POST   | `/api/uploads/{id}/chat`          | Ask Claude about the upload          |
| GET    | `/api/uploads/{id}/alerts`        | Export SIEM alerts                   |
| GET    | `/api/uploads/{id}/attack-layer`  | Export MITRE ATT&CK Navigator layer  |

Interactive docs at `/docs` when the backend is running.

---
