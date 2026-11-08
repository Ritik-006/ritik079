import os
import tempfile
import unittest

from app import create_app
from extensions import db
from models import BlockedDomain, Report, Scan, User

SCAM = "URGENT: Your account will be blocked. Verify your password immediately at http://secure-login-example.invalid"


class AppTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "RATE_LIMIT_PER_MIN": 1000,
                               "SQLALCHEMY_DATABASE_URI": f"sqlite:///{self.path}",
                               "ADMIN_EMAIL": "boss@example.com", "ADMIN_PASSWORD": "AdminPass123"})
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()
        os.remove(self.path)

    def register(self, client, name="alice", email="alice@example.com"):
        return client.post("/register", data={"username": name, "email": email,
                                              "password": "password123", "confirm": "password123"},
                           follow_redirects=True)

    def api_key(self, name="alice"):
        with self.app.app_context():
            return User.query.filter_by(username=name).first().api_key


class WebTests(AppTestCase):
    def test_health(self):
        data = self.client.get("/health").get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["database"], "ok")

    def test_anonymous_scan_stores_no_text(self):
        resp = self.client.post("/", data={"message": SCAM})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SCREENING RESULT", resp.data)
        with self.app.app_context():
            scan = Scan.query.one()
            self.assertIsNone(scan.text)
            self.assertIsNone(scan.user_id)

    def test_register_login_history_flow(self):
        self.register(self.client)
        self.client.post("/", data={"message": SCAM, "save": "on"})
        self.client.post("/", data={"message": "See you at the 3 PM meeting."})  # not saved
        page = self.client.get("/history")
        self.assertIn(b"URGENT", page.data)
        with self.app.app_context():
            self.assertEqual(Scan.query.filter(Scan.user_id.isnot(None)).count(), 1)

    def test_scans_are_private_between_users(self):
        self.register(self.client)
        self.client.post("/", data={"message": SCAM, "save": "on"})
        other = self.app.test_client()
        self.register(other, "bob", "bob@example.com")
        self.assertEqual(other.get("/scan/1").status_code, 404)

    def test_wrong_password_rejected(self):
        self.register(self.client)
        fresh = self.app.test_client()
        resp = fresh.post("/login", data={"identity": "alice", "password": "nope"})
        self.assertEqual(resp.status_code, 401)

    def test_open_redirect_blocked(self):
        self.register(self.client)
        fresh = self.app.test_client()
        resp = fresh.post("/login?next=//evil.com", data={"identity": "alice", "password": "password123"})
        self.assertNotIn("evil.com", resp.headers["Location"])

    def test_admin_required(self):
        self.register(self.client)
        self.assertEqual(self.client.get("/admin/").status_code, 403)

    def test_report_confirm_blocks_domain_and_raises_risk(self):
        self.client.post("/report", data={"category": "Phishing",
                                          "content": "Fake delivery text with link http://pay-now.badsite.example/x"})
        admin = self.app.test_client()
        admin.post("/login", data={"identity": "admin", "password": "AdminPass123"})
        self.assertEqual(admin.get("/admin/").status_code, 200)
        admin.post("/admin/reports/1/confirm")
        with self.app.app_context():
            self.assertEqual(Report.query.one().status, "confirmed")
            self.assertTrue(BlockedDomain.query.filter_by(domain="pay-now.badsite.example").first())
        data = self.client.post("/api/v1/analyze", json={"message": "hi http://pay-now.badsite.example"}).get_json()
        self.assertTrue(data["blocklist_hit"])
        self.assertGreaterEqual(data["risk"], 85)

    def test_delete_account_removes_data(self):
        self.register(self.client)
        self.client.post("/", data={"message": SCAM, "save": "on"})
        self.client.post("/account/delete", data={"confirm": "DELETE"})
        with self.app.app_context():
            self.assertEqual(User.query.filter_by(username="alice").count(), 0)
            self.assertEqual(Scan.query.filter(Scan.text.isnot(None)).count(), 0)


class ApiTests(AppTestCase):
    def test_analyze_anonymous(self):
        data = self.client.post("/api/v1/analyze", json={"message": SCAM}).get_json()
        self.assertGreater(data["risk"], 35)
        self.assertIsNone(data["scan_id"])

    def test_analyze_validation(self):
        self.assertEqual(self.client.post("/api/v1/analyze", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/v1/analyze", data="notjson").status_code, 400)

    def test_key_required_and_full_lifecycle(self):
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 401)
        self.register(self.client)
        h = {"X-API-Key": self.api_key()}
        scan = self.client.post("/api/v1/analyze", json={"message": SCAM}, headers=h).get_json()
        self.assertIsNotNone(scan["scan_id"])
        listing = self.client.get("/api/v1/scans", headers=h).get_json()
        self.assertEqual(listing["total"], 1)
        sid = scan["scan_id"]
        self.assertEqual(self.client.get(f"/api/v1/scans/{sid}", headers=h).status_code, 200)
        fb = self.client.post(f"/api/v1/scans/{sid}/feedback", json={"verdict": "scam"}, headers=h)
        self.assertEqual(fb.get_json()["verdict"], "scam")
        self.assertEqual(self.client.post(f"/api/v1/scans/{sid}/feedback", json={"verdict": "x"}, headers=h).status_code, 400)
        self.assertEqual(self.client.delete(f"/api/v1/scans/{sid}", headers=h).status_code, 204)
        self.assertEqual(self.client.get(f"/api/v1/scans/{sid}", headers=h).status_code, 404)

    def test_invalid_key_rejected_on_analyze(self):
        resp = self.client.post("/api/v1/analyze", json={"message": "hi"}, headers={"X-API-Key": "bogus"})
        self.assertEqual(resp.status_code, 401)

    def test_stats_and_reports(self):
        self.client.post("/api/v1/analyze", json={"message": SCAM})
        stats = self.client.get("/api/v1/stats").get_json()
        self.assertEqual(stats["total_scans"], 1)
        resp = self.client.post("/api/v1/reports", json={"content": "Scam text here please review", "category": "Job scam"})
        self.assertEqual(resp.status_code, 201)

    def test_rate_limit(self):
        self.app.config["RATE_LIMIT_PER_MIN"] = 2
        codes = [self.client.post("/api/v1/analyze", json={"message": "hi there"},
                                  headers={"X-Forwarded-For": "1"}).status_code for _ in range(4)]
        self.assertIn(429, codes)


if __name__ == "__main__":
    unittest.main()
