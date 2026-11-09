"""ScamShield AI — application factory and entry point."""
import click
from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from extensions import csrf, db, login_manager
from models import User


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)

    # Fail closed on production deployments instead of silently using the
    # development secret key or an ephemeral SQLite database.
    if app.config.get("APP_ENV") == "production":
        problems = []
        secret = app.config.get("SECRET_KEY") or ""
        database_uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
        if secret == "dev-only-change-me" or len(secret) < 32:
            problems.append("SECRET_KEY must be a generated secret of at least 32 characters")
        if not database_uri.startswith(("postgresql://", "postgresql+")):
            problems.append("DATABASE_URL must point to PostgreSQL for persistent production storage")
        if not app.config.get("SESSION_COOKIE_SECURE"):
            problems.append("COOKIE_SECURE must be 1 when deployed over HTTPS")
        if not app.config.get("ADMIN_EMAIL") or not app.config.get("ADMIN_PASSWORD"):
            problems.append("ADMIN_EMAIL and ADMIN_PASSWORD must be configured")
        elif len(app.config["ADMIN_PASSWORD"]) < 12:
            problems.append("ADMIN_PASSWORD must be at least 12 characters")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))

    if app.config["TRUST_PROXY"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    import admin, api, auth, services, web
    for module in (web, auth, api, admin):
        app.register_blueprint(module.bp)

    with app.app_context():
        db.create_all()
        _seed_admin(app)
        services.get_detector()  # train once at startup

    @app.get("/health")
    def health():
        detector = services.get_detector()
        try:
            db.session.execute(db.text("SELECT 1"))
            database = "ok"
        except Exception:
            database = "error"
        return jsonify(status="ok" if database == "ok" else "degraded", database=database,
                       quantum_available=detector.quantum.available)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        return response

    messages = {403: "You do not have permission to view this page.",
                404: "We could not find that page.",
                413: "That input is too large.",
                429: "Too many requests. Please wait a minute and try again.",
                500: "Something went wrong on our side."}

    def make_handler(code):
        def handler(error):
            if request.path.startswith("/api/"):
                return jsonify(error=messages[code]), code
            return render_template("error.html", code=code, message=messages[code]), code
        return handler

    for code in messages:
        app.register_error_handler(code, make_handler(code))

    _register_cli(app)
    return app


def _seed_admin(app):
    email, password = app.config.get("ADMIN_EMAIL"), app.config.get("ADMIN_PASSWORD")
    if email and password and not User.query.filter_by(email=email.lower()).first():
        user = User(username=app.config["ADMIN_USERNAME"], email=email.lower(), is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def _register_cli(app):
    @app.cli.command("create-admin")
    @click.argument("username")
    @click.argument("email")
    @click.password_option()
    def create_admin(username, email, password):
        """Create an administrator account."""
        user = User(username=username, email=email.lower(), is_admin=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Admin '{username}' created.")

    @app.cli.command("retrain")
    def retrain_cmd():
        """Retrain the classifier from confirmed reports and user verdicts."""
        import services
        services.get_detector()
        click.echo(f"Trained on {services.retrain()} examples.")

    @app.cli.command("reset-db")
    @click.confirmation_option(prompt="This deletes ALL data. Continue?")
    def reset_db():
        """Drop and recreate every table."""
        db.drop_all()
        db.create_all()
        click.echo("Database reset.")


app = create_app()

if __name__ == "__main__":
    # Local development server. For production use: gunicorn app:app
    app.run(host="127.0.0.1", port=5000, debug=False)
