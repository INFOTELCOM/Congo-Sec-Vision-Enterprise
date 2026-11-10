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
        def test_verify_supabase_user(auth):
            users = {
                "Bearer unit-test-admin-token-unique": {
                    "id": "admin-id", "email": "admin@example.test",
                    "app_metadata": {"csv_role": "admin"}
                },
                "Bearer unit-test-analyst-token": {
                    "id": "analyst-id", "email": "analyst@example.test",
                    "app_metadata": {"csv_role": "analyst"}
                },
                "Bearer unit-test-responder-token": {
                    "id": "responder-id", "email": "responder@example.test",
                    "app_metadata": {"csv_role": "incident_responder"}
                },
                "Bearer unit-test-viewer-token": {
                    "id": "viewer-id", "email": "viewer@example.test",
                    "app_metadata": {"csv_role": "viewer"}
                },
            }
            if auth not in users:
                raise HTTPException(401, "Invalid test session")
            return users[auth]
        api_module.verify_supabase_user = test_verify_supabase_user
        cls.client = TestClient(app)
        cls.headers = {"Authorization": "Bearer unit-test-admin-token-unique"}
        cls.analyst_headers = {"Authorization": "Bearer unit-test-analyst-token"}
        cls.responder_headers = {"Authorization": "Bearer unit-test-responder-token"}
        cls.viewer_headers = {"Authorization": "Bearer unit-test-viewer-token"}

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

    def test_role_permissions(self):
        self.assertEqual(self.client.get("/api/overview", headers=self.viewer_headers).status_code, 200)
        self.assertEqual(
            self.client.post("/api/incidents", headers=self.viewer_headers, json={"title":"Viewer must be blocked"}).status_code,
            403
        )
        self.assertEqual(
            self.client.post("/api/team", headers=self.analyst_headers, json={"username":"blocked","display_name":"Blocked","role":"analyst"}).status_code,
            403
        )
        self.assertEqual(self.client.get("/api/audit", headers=self.analyst_headers).status_code, 200)
        created = self.client.post("/api/incidents", headers=self.responder_headers, json={"title":"Responder test","severity":"low"})
        self.assertEqual(created.status_code, 200)

    def test_authorized_private_network_discovery(self):
        import app.main as api_module
        original = api_module.discover_network
        api_module.discover_network = lambda cidr: [
            {"ip_address": "192.168.50.10", "hostname": "lab-host"}
        ]
        try:
            response = self.client.post(
                "/api/network/discovery",
                headers=self.analyst_headers,
                json={"cidr": "192.168.50.0/24"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["hosts_reachable"], 1)
            saved = self.client.get("/api/network/discovery", headers=self.headers)
            self.assertEqual(saved.status_code, 200)
            self.assertEqual(saved.json()[0]["ip_address"], "192.168.50.10")
            blocked = self.client.post(
                "/api/network/discovery",
                headers=self.viewer_headers,
                json={"cidr": "192.168.50.0/24"}
            )
            self.assertEqual(blocked.status_code, 403)
            invalid = self.client.post(
                "/api/network/discovery",
                headers=self.headers,
                json={"cidr": "8.8.8.0/24"}
            )
            self.assertEqual(invalid.status_code, 400)
        finally:
            api_module.discover_network = original

    def test_agent_enrollment_persists_automatic_lan_observations(self):
        enrollment_headers = {"Authorization": "Bearer unit-test-enrollment-token-unique"}
        response = self.client.post(
            "/api/agents/enroll",
            headers=enrollment_headers,
            json={
                "hostname": "endpoint-lan-test",
                "platform": "Linux",
                "ip_addresses": [{"address": "192.168.50.20"}],
                "interfaces": [{"address": "192.168.50.20", "netmask": "255.255.255.0"}],
                "software": [],
                "network_discoveries": [
                    {"cidr": "192.168.50.0/24", "ip_address": "192.168.50.30", "hostname": "lan-device"}
                ]
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["network_hosts_discovered"], 1)
        rows = self.client.get("/api/network/discovery", headers=self.headers).json()
        observed = [x for x in rows if x["ip_address"] == "192.168.50.30"]
        self.assertTrue(observed)
        self.assertEqual(observed[0]["source"], "agent-icmp")

    def test_audit_and_team(self):
        member = self.client.post("/api/team", headers=self.headers, json={"username":"analyst1","display_name":"Analyst One","role":"analyst"})
        self.assertEqual(member.status_code, 200)
        self.assertGreaterEqual(len(self.client.get("/api/audit", headers=self.headers).json()), 1)

if __name__ == "__main__":
    unittest.main()
