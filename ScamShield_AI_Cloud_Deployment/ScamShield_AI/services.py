"""Business logic shared by the web UI, the REST API and the CLI."""
import hashlib
from datetime import timedelta
from urllib.parse import urlparse

from sqlalchemy import func

from detector import ScamDetector, URL_RE
from extensions import db
from models import BlockedDomain, Report, Scan, User, utcnow

_detector = None


def get_detector():
    global _detector
    if _detector is None:
        _detector = ScamDetector()
        retrain()  # fold in confirmed reports / user verdicts already in the database
    return _detector


# ---------- blocklist ----------
def extract_hosts(text):
    hosts = []
    for raw in URL_RE.findall(text or ""):
        cleaned = raw.rstrip(".,);]!?}")
        candidate = cleaned if cleaned.lower().startswith(("http://", "https://")) else "http://" + cleaned
        host = (urlparse(candidate).hostname or "").lower()
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def blocked_match(host):
    if not host:
        return None
    parts = host.split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)] or [host]
    return BlockedDomain.query.filter(BlockedDomain.domain.in_(candidates)).first()


def add_blocked_domain(domain, reason="Reported as a scam"):
    domain = domain.strip().lower().lstrip(".")
    if not domain or BlockedDomain.query.filter_by(domain=domain).first():
        return None
    entry = BlockedDomain(domain=domain, reason=reason[:255])
    db.session.add(entry)
    return entry


def _apply_blocklist(result):
    result["blocklist_hit"] = False
    for item in result["urls"]:
        match = blocked_match(item["host"])
        if match:
            item["notes"].append(f"Domain is on the ScamShield community blocklist ({match.reason}).")
            result["blocklist_hit"] = True
    if result["blocklist_hit"]:
        result["signals"] = [s for s in result["signals"] if not s.startswith("No listed warning phrase")]
        result["signals"].append("Contains a domain reported as a scam by the community.")
        result["risk"] = max(result["risk"], 85)
        result["label"], result["level"] = ScamDetector.classify(result["risk"])
    return result


# ---------- scanning ----------
def run_scan(text, user=None, source="web", save=True):
    """Analyze text and persist the outcome. Text is only stored for a logged-in user who opts in."""
    result = _apply_blocklist(get_detector().analyze(text))
    keep = bool(user and save)
    scan = Scan(
        user_id=user.id if keep else None,
        text=text if keep else None,
        text_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        risk=result["risk"], level=result["level"], result=result, source=source,
    )
    db.session.add(scan)
    db.session.commit()
    return scan, result


# ---------- reports & learning ----------
def create_report(content, category, user=None, scan_id=None):
    if category not in Report.CATEGORIES:
        category = "Other"
    report = Report(content=content, category=category, user_id=user.id if user else None, scan_id=scan_id)
    db.session.add(report)
    db.session.commit()
    return report


def confirm_report(report):
    report.status = "confirmed"
    added = []
    for host in extract_hosts(report.content):
        if add_blocked_domain(host, f"Confirmed report: {report.category}"):
            added.append(host)
    db.session.commit()
    return added


def retrain():
    """Retrain the classical model using admin-confirmed reports and users' own verdicts."""
    extra = [(r.content, 1) for r in Report.query.filter_by(status="confirmed")]
    extra += [(s.text, 1 if s.verdict == "scam" else 0)
              for s in Scan.query.filter(Scan.text.isnot(None), Scan.verdict.isnot(None))]
    return _detector.retrain(extra) if _detector else 0


# ---------- statistics ----------
def scan_stats(user=None):
    query = Scan.query.filter_by(user_id=user.id) if user else Scan.query
    total = query.count()
    levels = {"High": 0, "Medium": 0, "Low": 0}
    for level, count in query.with_entities(Scan.level, func.count()).group_by(Scan.level):
        levels[level] = count
    average = query.with_entities(func.avg(Scan.risk)).scalar()
    today = utcnow().date()
    daily = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        start = utcnow().replace(year=day.year, month=day.month, day=day.day, hour=0, minute=0, second=0, microsecond=0)
        count = query.filter(Scan.created_at >= start, Scan.created_at < start + timedelta(days=1)).count()
        daily.append({"date": day.strftime("%a %d"), "count": count})
    return {"total_scans": total, "by_level": levels,
            "average_risk": round(float(average), 1) if average is not None else 0,
            "last_7_days": daily}


def global_stats():
    stats = scan_stats()
    stats.update({"users": User.query.count(),
                  "blocked_domains": BlockedDomain.query.count(),
                  "reports": {s: Report.query.filter_by(status=s).count()
                              for s in ("pending", "confirmed", "rejected")}})
    return stats
