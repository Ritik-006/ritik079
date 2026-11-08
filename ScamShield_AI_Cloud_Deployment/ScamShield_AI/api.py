"""JSON REST API (v1). Authenticated endpoints use the X-API-Key header (see /account)."""
from functools import wraps

from flask import Blueprint, g, jsonify, request

from extensions import csrf, db
from models import Report, Scan, User
from ratelimit import rate_limited
import services

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)  # API uses key auth, not cookies


def _error(message, status):
    return jsonify(error=message), status


def _load_key_user():
    key = request.headers.get("X-API-Key")
    if not key:
        return None, False
    user = User.query.filter_by(api_key=key).first()
    return user, True


def api_key_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user, supplied = _load_key_user()
        if user is None:
            return _error("Missing or invalid X-API-Key header.", 401)
        g.api_user = user
        return view(*args, **kwargs)
    return wrapper


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


@bp.post("/analyze")
@rate_limited
def analyze():
    user, supplied = _load_key_user()
    if supplied and user is None:
        return _error("Invalid X-API-Key header.", 401)
    data = _json_body()
    text = str(data.get("message") or "").strip()[:10000]
    if not text:
        return _error("JSON body must include a non-empty 'message' field.", 400)
    save = data.get("save", True) is not False
    scan, result = services.run_scan(text, user, "api", save=save)
    payload = dict(result)
    payload["scan_id"] = scan.id if scan.user_id else None
    return jsonify(payload)


@bp.get("/me")
@api_key_required
def me():
    return jsonify(g.api_user.to_dict())


@bp.get("/scans")
@api_key_required
def list_scans():
    limit = min(max(request.args.get("limit", 20, type=int), 1), 100)
    offset = max(request.args.get("offset", 0, type=int), 0)
    query = Scan.query.filter_by(user_id=g.api_user.id)
    level = request.args.get("level")
    if level in ("High", "Medium", "Low"):
        query = query.filter_by(level=level)
    total = query.count()
    rows = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    return jsonify(total=total, limit=limit, offset=offset, items=[s.summary() for s in rows])


def _own_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    return scan if scan and scan.user_id == g.api_user.id else None


@bp.get("/scans/<int:scan_id>")
@api_key_required
def get_scan(scan_id):
    scan = _own_scan(scan_id)
    return jsonify(scan.to_dict()) if scan else _error("Scan not found.", 404)


@bp.delete("/scans/<int:scan_id>")
@api_key_required
def delete_scan(scan_id):
    scan = _own_scan(scan_id)
    if not scan:
        return _error("Scan not found.", 404)
    Report.query.filter_by(scan_id=scan.id).update({"scan_id": None})
    db.session.delete(scan)
    db.session.commit()
    return "", 204


@bp.post("/scans/<int:scan_id>/feedback")
@api_key_required
def feedback(scan_id):
    scan = _own_scan(scan_id)
    if not scan:
        return _error("Scan not found.", 404)
    verdict = _json_body().get("verdict")
    if verdict not in ("scam", "safe"):
        return _error("'verdict' must be 'scam' or 'safe'.", 400)
    scan.verdict = verdict
    db.session.commit()
    return jsonify(scan.summary())


@bp.post("/reports")
@rate_limited
def create_report():
    user, supplied = _load_key_user()
    if supplied and user is None:
        return _error("Invalid X-API-Key header.", 401)
    data = _json_body()
    content = str(data.get("content") or "").strip()
    if not 10 <= len(content) <= 5000:
        return _error("'content' must be 10-5000 characters.", 400)
    report = services.create_report(content, data.get("category", "Other"), user)
    return jsonify(report.to_dict()), 201


@bp.get("/stats")
@rate_limited
def stats():
    return jsonify(services.global_stats())
