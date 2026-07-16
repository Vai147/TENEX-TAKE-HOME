# Tenex Take-Home — Implementation Plan

Phase-wise build. Stack: Next.js + TS (frontend), Python + FastAPI (backend), Postgres, Claude (LLM). Log format: ZScaler Web Proxy.

---

## Phase 1 — Scaffold ✅
- [x] `docker-compose.yml`: `frontend`, `backend`, `db` (Postgres) + file volume
- [x] Backend skeleton: FastAPI app, `requirements.txt`, `Dockerfile`, `/health`
- [x] Frontend skeleton: Next.js + TS + Tailwind, `Dockerfile` (build verified)
- [x] DB: SQLAlchemy setup, tables (`users`, `uploads`, `log_entries`, `anomaly_findings`, `analysis_summary`) via `create_all` on startup
- [x] `examples/`: sample ZScaler logs (clean + anomalous)
- [x] `.env.example`, `.gitignore`

## Phase 2 — Auth
- [ ] `POST /api/auth/login` → verify bcrypt → JWT
- [ ] JWT verify dependency (injects user, else 401)
- [ ] Seed one user at startup
- [ ] Frontend `/login` page: form → store JWT → redirect

## Phase 3 — Upload + Parser
- [ ] `POST /api/uploads` (multipart, JWT): validate ext/size, save to volume, create `Upload` row
- [ ] `parser.py`: raw ZScaler log → `LogEntry[]`, persist
- [ ] `GET /api/uploads/:id` → result
- [ ] Frontend `/upload` page: drag-drop → POST → redirect to result

## Phase 4 — Anomaly Engine (deterministic)
- [ ] 5 detectors, each pure `(entries) → findings` + confidence 0–1:
  - [ ] IP burst
  - [ ] Blocked-action spike
  - [ ] Rare user-agent
  - [ ] Byte-volume anomaly
  - [ ] Off-hours access
- [ ] Weighted scoring + rank top-N
- [ ] Persist `anomaly_findings`
- [ ] Unit tests for detectors

## Phase 5 — Claude Layer
- [ ] `llm.py`: send aggregates + top findings → Claude (structured output/tool-use)
- [ ] Jobs: (1) SOC timeline narrative, (2) anomaly explanation + severity
- [ ] Pydantic schema (`LlmAnalysis`) validation
- [ ] Safety ladder: extract → parse → validate → semantic check → 1 repair retry → deterministic fallback (`llm_ok=false`)
- [ ] `GET /api/uploads/:id/anomalies`

## Phase 6 — Frontend Results
- [ ] `/results/:id`:
  - [ ] Summary cards (total, flagged, severity mix)
  - [ ] Timeline (Claude narrative)
  - [ ] Entries table (paginated, anomalies row-highlighted)
  - [ ] Anomaly panel (reason + confidence badge + severity)
  - [ ] Chart (requests over time / top IPs — recharts)

## Phase 7 — Polish + Deliverables
- [ ] `README.md`: local setup + AI approach explanation
- [ ] Verify example logs trigger anomalies
- [ ] Security pass: env secrets, CORS locked, input validation
- [ ] Walkthrough recording
- [ ] Optional: deploy to Render/Vercel + live link
