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

- Frontend → http://localhost:3000
- Backend  → http://localhost:8000 (Swagger at `/docs`)
- Postgres → host port **5433** (container 5432)

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

