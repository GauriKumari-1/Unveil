# Cyber Triage Tool — SIH1744

Digital-forensics evidence triage: ingests 4 evidence log sources, classifies
them, normalizes them into one common event timeline, correlates suspicious
chains (USB exfiltration / external upload) within a 30-minute window, scores
severity explainably, extracts IOCs, and serves it all to a live dashboard.

One process runs the whole thing — FastAPI serves both the JSON API and the
dashboard, so there's nothing to deploy separately for the demo.

## Run it (takes ~1 minute)

Run these from the project's top folder (the one containing `backend/` and
`frontend/`):

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r backend/requirements.txt
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000** — the dashboard loads and auto-fetches the
built-in demo case (`CASE-DEMO`, the four sample CSVs under
`backend/data/sample/`).

## Demo flow for the jury

1. Dashboard opens, auto-loads the demo case, stats populate live from the
   backend (not hardcoded).
2. Click **ALERTS** tab (or an alert card) → shows the two correlated
   chains (USB exfiltration + Gmail/browser upload), each with severity,
   risk score breakdown, and the exact triggering events.
3. Click **TIMELINE** → the flagged rows are highlighted; search/filter by
   source works against the real event list.
4. Click **IOCs** → extracted IPs/URLs/domains/hashes/usernames, each
   traceable back to its source event, copy-to-clipboard works.
5. To show it isn't hardcoded: zip the four CSVs in
   `backend/data/sample/` yourself (or edit a timestamp) and use
   **UPLOAD EVIDENCE ZIP → ANALYZE** on the dashboard — a brand-new case ID
   is created and the whole pipeline re-runs live.
6. **EXPORT REPORT** downloads a plain-text case summary.

## What's real vs. what to say if asked

- Everything on the dashboard comes from live API calls (`/summary`,
  `/timeline`, `/alerts`, `/iocs`, `/cases/{id}`) — nothing is hardcoded in
  the frontend.
- Correlation is two explicit, explainable rules (not ML): sensitive file
  access/copy followed within 30 minutes by a USB connection, or by an
  external browser upload.
- Severity is a transparent additive score (sensitive access +20, copy +20,
  USB +25, external upload +30, known-bad hash +40) mapped to
  LOW/MEDIUM/HIGH/CRITICAL — shown with its full breakdown, not just a label.
- Malformed/missing files never crash the server — `/upload` and the
  classifier return clear JSON errors instead.

## Project layout

```
backend/
  app.py            FastAPI app + all endpoints (thin)
  models.py         Event / IOC / Alert / CaseResult schemas
  config.py         evidence-type map, required columns, scoring weights
  classifier.py     filename -> evidence type (or "unsupported")
  parser.py         raw CSV -> per-source records
  normalizer.py     records -> common Event schema, merged + time-sorted
  ioc.py            regex extraction of IP/URL/DOMAIN/HASH/USERNAME
  correlation.py    the two correlation rules + severity scoring
  data/sample/      the fixed demo evidence set (one coherent incident +
                     innocent events, so it isn't just "USB = suspicious")
  test_stages.py    pytest smoke tests for the pipeline
frontend/
  index.html        single-file dashboard (no build step), calls the API
```

## Endpoints

- `GET /health`
- `POST /upload` — multipart ZIP of the 4 CSVs → new case
- `GET /summary?case_id=` — dashboard headline numbers
- `GET /timeline?case_id=` — unified sorted event list
- `GET /alerts?case_id=` — correlated, explainable alerts
- `GET /iocs?case_id=` — extracted indicators
- `GET /cases/{case_id}` — full case object (files + events + alerts + iocs)

Omitting `case_id` (or passing `CASE-DEMO`) always returns the built-in demo
case.

## After the base demo is accepted (stretch, don't touch before then)

- Hash-matching against a bigger known-bad list
- Multi-case switcher in the UI
- PDF report export instead of .txt
- Real `.evtx` / browser-SQLite ingestion
