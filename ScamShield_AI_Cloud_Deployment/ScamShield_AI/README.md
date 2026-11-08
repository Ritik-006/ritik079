# Windows one-click launch

For Windows users, see `START_HERE.txt`.

- Run `SETUP_ONCE.bat` once to create `.venv` and install dependencies.
- Run `CREATE_DESKTOP_SHORTCUT.bat` once to add a desktop shortcut.
- Later, double-click `START_SCAMSHIELD.bat` or the desktop shortcut.

The launcher starts the local Flask server and opens the app at
`http://127.0.0.1:5000`. Keep the server window open while using it.

# ScamShield AI — full-stack app

Screens messages and URLs for scams with a classical ML model, explainable rules, an experimental Qiskit circuit and a **community-powered blocklist**. Includes accounts, a database, a REST API and an admin panel.

## Features
- **Analyzer**: TF-IDF + Logistic Regression, rule signals, URL checks, optional 4-qubit Qiskit score
- **Accounts**: register / login / logout, password hashing, CSRF protection
- **Scan history** (saved only if you tick "Save to my history"), filters, pagination, delete
- **Feedback loop**: mark a scan "scam" or "safe"; admins can retrain the model
- **Community reports → blocklist**: reports are moderated; confirmed links raise the risk score of future scans
- **Dashboard**: personal and community statistics
- **REST API** with per-user API keys (see `docs/API.md`)
- **Admin panel**: moderate reports, manage blocklist, retrain model
- **Database**: SQLite by default (zero setup), PostgreSQL via `DATABASE_URL`
- Rate limiting, security headers, privacy-first storage, Docker support, 18 automated tests

## Quick start (Windows PowerShell)
```powershell
cd path\to\ScamShield_AI
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
macOS/Linux: `source .venv/bin/activate` instead of the activate line. Open http://127.0.0.1:5000.

The database file is created automatically at `instance/scamshield.db`. No manual DB setup is needed.

### Create an admin
Either set environment variables before starting (account is created on first start):
```powershell
$env:ADMIN_EMAIL="you@example.com"; $env:ADMIN_PASSWORD="StrongPass123"; python app.py
```
or use the CLI: `flask --app app create-admin myname me@example.com`

### Other commands
```
flask --app app retrain     # retrain from confirmed reports + user verdicts
flask --app app reset-db    # DANGER: wipe all data
python -m unittest discover -s tests -v
```

## Configuration
Copy `.env.example` and set values as environment variables. Key ones: `SECRET_KEY` (**required in production**), `DATABASE_URL`, `COOKIE_SECURE=1` (HTTPS), `TRUST_PROXY=1` (behind a proxy), `RATE_LIMIT_PER_MIN`.

## Run with Docker + PostgreSQL
```
docker compose up --build
```
App at http://localhost:8000 (PostgreSQL included). Set `SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` in your shell first.

## Production (without Docker)
`gunicorn -b 0.0.0.0:8000 -w 2 app:app` behind nginx/Caddy with HTTPS. Set `SECRET_KEY`, `COOKIE_SECURE=1`, `TRUST_PROXY=1`, and a PostgreSQL `DATABASE_URL`. Note: the rate limiter is per-process; use a shared store such as Redis for multi-server setups.

## Project structure
```
ScamShield_AI/
├── app.py                 app factory, error pages, CLI, entry point
├── config.py              env-based settings
├── extensions.py          db, login manager, CSRF
├── models.py              User, Scan, Report, BlockedDomain
├── services.py            scanning, blocklist, reports, retraining, stats
├── detector.py            classical ML + rules (+ quantum fusion)
├── quantum_classifier.py  experimental Qiskit circuit
├── web.py  auth.py  api.py  admin.py   blueprints
├── ratelimit.py           in-memory rate limiter
├── templates/  static/    UI
├── tests/                 detector, web and API tests
├── docs/                  architecture, API, database schema
├── Dockerfile  docker-compose.yml  .env.example
```

## Privacy design
- Anonymous scans: only a SHA-256 hash and the score are stored, never the text.
- Logged-in scans: text is stored only if "Save to my history" is ticked.
- Users can delete individual scans or their whole account.

## Limitations
The training set is tiny and illustrative, and the quantum parameters are untrained demo values (not evidence of quantum advantage). A low score never guarantees safety. Before real use, train on a proper labelled dataset and report precision/recall/F1 against a classical baseline. Admins should review reports carefully before confirming, since confirmation blocks every domain in the report.


## Deploy online (public website + private admin)

See [`DEPLOY_RENDER.md`](DEPLOY_RENDER.md). A Render Blueprint is included in `render.yaml`; review its paid PostgreSQL resource and enter admin credentials in Render's setup prompts. Never commit secrets.
