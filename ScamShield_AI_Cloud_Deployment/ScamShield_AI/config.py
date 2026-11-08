"""Application configuration. Everything can be overridden with environment variables (.env)."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _database_url():
    url = os.environ.get("DATABASE_URL")
    if not url:
        (BASE_DIR / "instance").mkdir(exist_ok=True)
        return f"sqlite:///{BASE_DIR / 'instance' / 'scamshield.db'}"
    # Some hosts still hand out the legacy "postgres://" scheme.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


class Config:
    APP_ENV = os.environ.get("APP_ENV", "development")
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    MAX_CONTENT_LENGTH = 64 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "30"))
    TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
    ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
