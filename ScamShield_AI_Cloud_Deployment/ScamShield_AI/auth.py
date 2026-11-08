"""Registration, login and logout."""
import re
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user, login_required

from extensions import db, login_manager
from models import User
from ratelimit import rate_limited

bp = Blueprint("auth", __name__)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and not urlparse(target).netloc:
        return target
    return url_for("web.index")


@bp.route("/register", methods=["GET", "POST"])
@rate_limited
def register():
    if current_user.is_authenticated:
        return redirect(url_for("web.index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-30 characters: letters, numbers or underscore.")
        if not EMAIL_RE.match(email) or len(email) > 255:
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != request.form.get("confirm", ""):
            errors.append("Passwords do not match.")
        if not errors and User.query.filter((User.username == username) | (User.email == email)).first():
            errors.append("That username or email is already registered.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email), 400
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Welcome to ScamShield AI! Your account is ready.", "success")
        return redirect(url_for("web.index"))
    return render_template("register.html", username="", email="")


@bp.route("/login", methods=["GET", "POST"])
@rate_limited
def login():
    if current_user.is_authenticated:
        return redirect(url_for("web.index"))
    if request.method == "POST":
        ident = request.form.get("identity", "").strip().lower()
        user = User.query.filter((User.email == ident) | (db.func.lower(User.username) == ident)).first()
        if user and user.check_password(request.form.get("password", "")):
            login_user(user, remember=request.form.get("remember") == "on")
            return redirect(_safe_next(request.args.get("next")))
        flash("Invalid username/email or password.", "error")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("web.index"))
