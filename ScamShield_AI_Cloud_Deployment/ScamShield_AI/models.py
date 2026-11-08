"""Database models: users, scans, community reports and the domain blocklist."""
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_api_key():
    return "ss_" + secrets.token_urlsafe(32)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False, default=new_api_key, index=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    scans = db.relationship("Scan", backref="user", lazy="dynamic")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {"id": self.id, "username": self.username, "email": self.email,
                "is_admin": self.is_admin, "created_at": self.created_at.isoformat()}


class Scan(db.Model):
    __tablename__ = "scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    text = db.Column(db.Text, nullable=True)           # only stored when a logged-in user saves it
    text_hash = db.Column(db.String(64), nullable=False, index=True)
    risk = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(10), nullable=False, index=True)
    result = db.Column(db.JSON, nullable=False)        # full analysis output
    verdict = db.Column(db.String(10), nullable=True)  # user feedback: "scam" | "safe"
    source = db.Column(db.String(10), default="web", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    def summary(self):
        preview = (self.text or "")[:120]
        return {"id": self.id, "risk": self.risk, "level": self.level,
                "label": self.result.get("label"), "preview": preview,
                "verdict": self.verdict, "source": self.source,
                "created_at": self.created_at.isoformat()}

    def to_dict(self):
        data = self.summary()
        data.update({"text": self.text, "result": self.result})
        return data


class Report(db.Model):
    __tablename__ = "reports"
    CATEGORIES = ["Phishing", "Fake prize / lottery", "Bank / OTP fraud", "Job scam",
                  "Investment scam", "Delivery / parcel scam", "Tech support scam", "Other"]
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    category = db.Column(db.String(40), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(10), default="pending", nullable=False, index=True)  # pending|confirmed|rejected
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    user = db.relationship("User")

    def to_dict(self):
        return {"id": self.id, "category": self.category, "content": self.content,
                "status": self.status, "scan_id": self.scan_id,
                "created_at": self.created_at.isoformat()}


class BlockedDomain(db.Model):
    __tablename__ = "blocked_domains"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), default="Reported as a scam")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
