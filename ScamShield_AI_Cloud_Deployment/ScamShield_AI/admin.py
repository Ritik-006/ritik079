"""Moderator tools: review reports, manage the blocklist, retrain the model."""
from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import db
from models import BlockedDomain, Report
import services

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


@bp.get("/")
@admin_required
def panel():
    status = request.args.get("status", "pending")
    reports = Report.query.filter_by(status=status).order_by(Report.created_at.desc()).limit(50).all()
    domains = BlockedDomain.query.order_by(BlockedDomain.created_at.desc()).limit(200).all()
    return render_template("admin.html", reports=reports, domains=domains,
                           status=status, stats=services.global_stats())


@bp.post("/reports/<int:report_id>/<action>")
@admin_required
def moderate(report_id, action):
    report = db.get_or_404(Report, report_id)
    if action == "confirm":
        added = services.confirm_report(report)
        flash("Report confirmed." + (f" Blocked: {', '.join(added)}." if added else ""), "success")
    elif action == "reject":
        report.status = "rejected"
        db.session.commit()
        flash("Report rejected.", "success")
    else:
        abort(404)
    return redirect(url_for("admin.panel"))


@bp.post("/blocklist")
@admin_required
def add_domain():
    domain = request.form.get("domain", "").strip().lower()
    if "." not in domain or " " in domain or "/" in domain:
        flash("Enter a bare domain such as scam-site.example (no http://, no path).", "error")
    elif services.add_blocked_domain(domain, request.form.get("reason", "").strip() or "Added by admin"):
        db.session.commit()
        flash(f"{domain} added to blocklist.", "success")
    else:
        flash("Domain already on the blocklist.", "warning")
    return redirect(url_for("admin.panel"))


@bp.post("/blocklist/<int:entry_id>/delete")
@admin_required
def remove_domain(entry_id):
    db.session.delete(db.get_or_404(BlockedDomain, entry_id))
    db.session.commit()
    flash("Domain removed from blocklist.", "success")
    return redirect(url_for("admin.panel"))


@bp.post("/retrain")
@admin_required
def retrain():
    services.get_detector()
    size = services.retrain()
    flash(f"Model retrained on {size} labelled examples.", "success")
    return redirect(url_for("admin.panel"))
