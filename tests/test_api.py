"""Smoke tests for Congo Sec Vision lab API. Run: pip install -r requirements-dev.txt && python -m unittest discover -s tests"""
import os, tempfile, unittest
from fastapi.testclient import TestClient

class ApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["SUPABASE_URL"] = "https://unit-test.supabase.co"
        os.environ["SUPABASE_PUBLISHABLE_KEY"] = "sb_publishable_unit_test"
        os.environ["AGENT_ENROLLMENT_TOKEN"] = "unit-test-enrollment-token-unique"
        os.environ["DATABASE_PATH"] = os.path.join(cls.tmp.name, "test.db")
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from app.main import app
        import app.main as api_module
        from fastapi import HTTPException
        def test_require_admin(auth):
            if auth != "Bearer unit-test-admin-token-unique":
                raise HTTPException(401, "Invalid test session")
            return "unit-test-admin"
        api_module.require_admin = test_require_admin
        cls.client = TestClient(app)
        cls.headers = {"Authorization": "Bearer unit-test-admin-token-unique"}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_health(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_auth_rejects_invalid_token(self):
        self.assertEqual(self.client.post("/api/auth/check", headers={"Authorization":"Bearer invalid"}).status_code, 401)

    def test_incident_lifecycle(self):
        created = self.client.post("/api/incidents", headers=self.headers, json={"title":"Unit test incident","severity":"high"})
        self.assertEqual(created.status_code, 200)
        iid = created.json()["id"]
        updated = self.client.patch(f"/api/incidents/{iid}", headers=self.headers, json={"status":"investigating"})
        self.assertEqual(updated.status_code, 200)
        rows = self.client.get("/api/incidents", headers=self.headers).json()
        self.assertEqual(rows[0]["status"], "investigating")

    def test_approval_is_record_only(self):
        r = self.client.post("/api/approvals", headers=self.headers, json={"title":"Test patch","description":"Lab approval"})
        self.assertEqual(r.status_code, 200)
        reviewed = self.client.post(f"/api/approvals/{r.json()['id']}/review", headers=self.headers, json={"decision":"approved"})
        self.assertEqual(reviewed.status_code, 200)
        self.assertEqual(reviewed.json()["execution"], "not-run")

    def test_audit_and_team(self):
        member = self.client.post("/api/team", headers=self.headers, json={"username":"analyst1","display_name":"Analyst One","role":"analyst"})
        self.assertEqual(member.status_code, 200)
        self.assertGreaterEqual(len(self.client.get("/api/audit", headers=self.headers).json()), 1)

    def test_cve_filters_triage_subscriptions_and_notifications(self):
        from app.main import conn
        sub = self.client.post("/api/cve/subscriptions", headers=self.headers,
                               json={"vendor":"Acme","product":"Widget"})
        self.assertEqual(sub.status_code, 200)
        with conn() as c:
            cur = c.execute("""INSERT INTO vulnerabilities(asset_id,cve_id,severity,title,status,source,created_at,
                software_name,software_version,vendor,match_confidence,cvss_score,epss_score,known_exploited)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("asset-test","CVE-2099-1234","critical","Test vulnerability","needs-validation","test","2026-01-01T00:00:00Z",
                 "Widget","1.0","Acme","candidate",9.8,0.75,1))
            vid = cur.lastrowid
            c.execute("""INSERT INTO cve_notifications(subscription_id,vulnerability_id,cve_id,event_type,title,severity,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (sub.json()["id"],vid,"CVE-2099-1234","new-cve","Test vulnerability","critical","2026-01-01T00:00:00Z"))
        filtered = self.client.get("/api/vulnerabilities?vendor=Acme&kev=true&min_cvss=9", headers=self.headers)
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(filtered.json()[0]["cve_id"], "CVE-2099-1234")
        updated = self.client.patch(f"/api/vulnerabilities/{vid}", headers=self.headers,
                                    json={"status":"under-analysis","assigned_to":"analyst1","tags":["important"]})
        self.assertEqual(updated.status_code, 200)
        history = self.client.get("/api/cve/history?cve_id=CVE-2099-1234", headers=self.headers)
        self.assertEqual(history.status_code, 200)
        notifications = self.client.get("/api/cve/notifications?unread_only=true", headers=self.headers)
        self.assertEqual(len(notifications.json()), 1)
        read = self.client.patch(f"/api/cve/notifications/{notifications.json()[0]['id']}", headers=self.headers)
        self.assertEqual(read.status_code, 200)
        self.assertEqual(self.client.get("/api/cve/notifications?unread_only=true", headers=self.headers).json(), [])

if __name__ == "__main__":
    unittest.main()
