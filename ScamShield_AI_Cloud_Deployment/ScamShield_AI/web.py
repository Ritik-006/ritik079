"""Browser-facing pages."""
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, logout_user

from extensions import db
from models import Report, Scan, new_api_key
from ratelimit import rate_limited
import services

bp = Blueprint("web", __name__)


def _owned_scan_or_404(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        abort(404)
    return scan


@bp.route("/", methods=["GET", "POST"])
@rate_limited
def index():
    result, scan, text = None, None, ""
    if request.method == "POST":
        text = request.form.get("message", "").strip()[:10000]
        if text:
            user = current_user if current_user.is_authenticated else None
            scan, result = services.run_scan(text, user, "web", save=request.form.get("save") == "on")
        else:
            flash("Paste a message or URL to analyze.", "warning")
    return render_template("index.html", result=result, scan=scan, text=text)


@bp.get("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    level = request.args.get("level")
    query = Scan.query.filter_by(user_id=current_user.id)
    if level in ("High", "Medium", "Low"):
        query = query.filter_by(level=level)
    pagination = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template("history.html", pagination=pagination, level=level)


@bp.get("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = _owned_scan_or_404(scan_id)
    return render_template("scan_detail.html", scan=scan, result=scan.result)


@bp.post("/scan/<int:scan_id>/feedback")
@login_required
def scan_feedback(scan_id):
    scan = _owned_scan_or_404(scan_id)
    verdict = request.form.get("verdict")
    if verdict in ("scam", "safe"):
        scan.verdict = verdict
        db.session.commit()
        flash("Thanks! Your verdict was saved and helps improve the model.", "success")
    return redirect(url_for("web.scan_detail", scan_id=scan.id))


@bp.post("/scan/<int:scan_id>/delete")
@login_required
def scan_delete(scan_id):
    scan = _owned_scan_or_404(scan_id)
    Report.query.filter_by(scan_id=scan.id).update({"scan_id": None})
    db.session.delete(scan)
    db.session.commit()
    flash("Scan deleted.", "success")
    return redirect(url_for("web.history"))


@bp.route("/report", methods=["GET", "POST"])
@rate_limited
def report():
    prefill, scan_id = "", request.args.get("scan_id", type=int)
    if request.method == "GET" and scan_id and current_user.is_authenticated:
        scan = db.session.get(Scan, scan_id)
        if scan and scan.user_id == current_user.id:
            prefill = scan.text or ""
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if len(content) < 10 or len(content) > 5000:
            flash("Please describe or paste the scam (10-5000 characters).", "error")
            return render_template("report.html", categories=Report.CATEGORIES, prefill=content), 400
        user = current_user if current_user.is_authenticated else None
        linked = request.form.get("scan_id", type=int)
        if linked:
            scan = db.session.get(Scan, linked)
            linked = scan.id if scan and user and scan.user_id == user.id else None
        services.create_report(content, request.form.get("category", "Other"), user, linked)
        flash("Report submitted. A moderator will review it. Thank you for helping others!", "success")
        return redirect(url_for("web.index"))
    return render_template("report.html", categories=Report.CATEGORIES, prefill=prefill, scan_id=scan_id)


@bp.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", mine=services.scan_stats(current_user),
                           community=services.global_stats())


@bp.get("/account")
@login_required
def account():
    return render_template("account.html")


@bp.post("/account/api-key")
@login_required
def regenerate_key():
    current_user.api_key = new_api_key()
    db.session.commit()
    flash("A new API key was generated. The old one no longer works.", "success")
    return redirect(url_for("web.account"))


@bp.post("/account/delete")
@login_required
def delete_account():
    if request.form.get("confirm") != "DELETE":
        flash('Type DELETE to confirm account deletion.', "error")
        return redirect(url_for("web.account"))
    user = current_user._get_current_object()
    Report.query.filter_by(user_id=user.id).update({"user_id": None})
    Report.query.filter(Report.scan_id.in_(db.session.query(Scan.id).filter_by(user_id=user.id))).update(
        {"scan_id": None}, synchronize_session=False)
    Scan.query.filter_by(user_id=user.id).delete()
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Your account and saved scans were permanently deleted.", "success")
    return redirect(url_for("web.index"))
