# Database schema (SQLAlchemy; tables are created automatically on startup)

- **users**: id, username (unique), email (unique), password_hash, api_key (unique), is_admin, created_at
- **scans**: id, user_id → users (nullable), text (nullable, only when saved), text_hash, risk, level, result (JSON), verdict (scam|safe), source (web|api), created_at
- **reports**: id, user_id → users (nullable), scan_id → scans (nullable), category, content, status (pending|confirmed|rejected), created_at
- **blocked_domains**: id, domain (unique), reason, created_at

For schema changes in a long-lived deployment, add Flask-Migrate (Alembic).
