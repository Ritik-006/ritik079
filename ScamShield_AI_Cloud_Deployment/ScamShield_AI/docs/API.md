# REST API v1

Base URL: `http://127.0.0.1:5000/api/v1`. Get your API key on the **Account** page. Send it as `X-API-Key: <key>`. Errors are JSON: `{"error": "..."}`. Rate limit: 30 requests/minute by default (HTTP 429).

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/analyze` | optional | Body `{"message": "...", "save": true}`. With a key the scan is saved to your history (`scan_id` returned); without one nothing is stored. |
| GET | `/me` | key | Current user |
| GET | `/scans?limit=20&offset=0&level=High` | key | Your saved scans |
| GET | `/scans/<id>` | key | Full scan with text and result |
| DELETE | `/scans/<id>` | key | Delete a scan (204) |
| POST | `/scans/<id>/feedback` | key | `{"verdict": "scam" \| "safe"}` |
| POST | `/reports` | optional | `{"content": "...", "category": "Phishing"}` → 201, pending moderation |
| GET | `/stats` | none | Aggregate community statistics |
| GET | `/health` (no `/api/v1`) | none | Liveness + DB check |

## Example
```bash
curl -X POST http://127.0.0.1:5000/api/v1/analyze \
  -H "Content-Type: application/json" -H "X-API-Key: ss_..." \
  -d '{"message": "URGENT: verify your password at http://secure-login.example"}'
```
Response (abridged):
```json
{"label": "Suspicious — verify independently", "risk": 52, "level": "Medium",
 "signals": ["Uses urgency or pressure", "..."], "urls": [{"url": "...", "host": "...", "notes": []}],
 "advice": ["..."], "models": {"classical_probability": 0.81, "quantum_probability": 0.37, "quantum_note": "..."},
 "blocklist_hit": false, "scan_id": 12}
```
