# Deploy ScamShield AI to Render (public website + private admin)

## Before you start

- Push this project to a GitHub repository that you control.
- Do not commit `.env`, passwords, API keys, `.venv`, or the `instance/` folder.
- Render's Blueprint creates a public web service and a managed PostgreSQL database.
- The web service is configured on Render's free compute plan. The PostgreSQL database uses the `basic-256mb` plan, which is paid. Check current Render pricing before creating resources; do not approve a paid plan unless you have permission from the account owner.
- The free web service may sleep when idle, so the first request after inactivity can take longer.

## Deploy

1. Sign in to Render and choose **New > Blueprint**.
2. Connect the GitHub repository containing this folder.
3. Render detects `render.yaml`. Review the resources and costs before applying.
4. When prompted, enter:
   - `ADMIN_EMAIL`: an email address you control.
   - `ADMIN_PASSWORD`: a unique password of at least 12 characters. Do not reuse an existing password.
5. Apply the Blueprint and wait for the web service and database to become available.
6. Open the generated `https://...onrender.com` address.
7. Register a normal public user account and test message/URL analysis.
8. Open `/login` and sign in using the configured administrator email and password. The administrator panel is at `/admin/`.

The admin account is created on the first app startup if the configured email does not already exist. If that email already belongs to a non-admin user, the app deliberately does not silently promote it. Use a fresh admin email for the first deployment.

## Important deployment notes

- The public analyzer does not require an account. User history and the admin panel require login.
- Anonymous scan text is not saved by the application; only the result, score and SHA-256 hash are stored. Logged-in scan text is saved only when the user chooses to save it.
- The model is a prototype with a small illustrative training set. Its score is not proof that a message is safe or fraudulent. Do not rely on it as the only fraud-protection measure.
- The Qiskit component is experimental and its demo parameters are not trained evidence of quantum advantage.
- This deployment uses one Gunicorn worker because the current rate limiter is in-memory and database table creation occurs during app initialization. For larger production traffic, add database migrations and a shared rate-limit store before scaling horizontally.
- Keep administrator credentials private. Never put them in source code or upload them to GitHub.
- The first deploy creates a fresh cloud database. Your local Windows SQLite accounts, scan history and reports are not automatically copied to it.
- `render.yaml` uses a Singapore region to reduce distance from India, but actual latency depends on network routing.

## Local verification

Run the detector tests with:

```bash
python -m unittest discover -s tests -v
```

The full web test suite requires the packages in `requirements.txt`.
