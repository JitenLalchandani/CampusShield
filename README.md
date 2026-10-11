# CampusShield — University Cybersecurity at Scale

CampusShield is a demonstration prototype for a privacy-aware campus threat-monitoring workflow.

## What works
- Express backend with health, summary, events, scan, and alert-action API endpoints.
- Rule-based detection for synthetic authentication failures, mock threat-intelligence matches, outbound-traffic spikes, and missing patches.
- Dashboard fetches data from the API and renders prioritized alerts.
- Run Scan creates a new **synthetic** event.
- Investigate / Contain records a demo action in server memory.
- Responsive dashboard UI.

## Important limitations
- All telemetry is synthetic; no real campus devices or services are monitored.
- The prototype uses in-memory data; state resets when the server restarts.
- Containment is only a status label. It does not block traffic, disable accounts, or modify devices.
- The rule-based detector is illustrative, not a production detection engine.
- No authentication, database persistence, or production hardening is included.

## Requirements
- Node.js 18+ recommended.
- npm.

## Run locally
Open Terminal and enter these commands from the folder where this project is extracted:

```bash
cd CampusShield
npm install
npm start
```

Then open http://localhost:3000 in your browser.

Stop the server with Ctrl+C.

## API endpoints
- `GET /api/health` — status
- `GET /api/summary` — dashboard metrics
- `GET /api/events` — events plus rule-based severity and recommendations
- `POST /api/scan` — add a synthetic event and analyse it
- `POST /api/alerts/:id/action` — record `{"action":"Investigate"}` or `{"action":"Contain"}`

## Suggested next steps for a real deployment
Integrate approved log sources (identity provider, DNS/firewall, endpoint management), add authentication and role-based access, store events in a database, add audit logging and retention controls, test detection precision/recall, and require human approval for disruptive actions.
