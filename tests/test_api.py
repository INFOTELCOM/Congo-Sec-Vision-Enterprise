"""Smoke tests for Congo Sec Vision lab API. Run: pip install -r requirements-dev.txt && python -m unittest discover -s tests"""
import os, tempfile, unittest
from fastapi.testclient import TestClient

class ApiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["ADMIN_TOKEN"] = "unit-test-admin-token-unique"
        os.environ["AGENT_ENROLLMENT_TOKEN"] = "unit-test-enrollment-token-unique"
        os.environ["DATABASE_PATH"] = os.path.join(cls.tmp.name, "test.db")
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from app.main import app
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

if __name__ == "__main__":
    unittest.main()
