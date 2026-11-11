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
        def test_require_roles(auth, allowed_roles):
            if auth != "Bearer unit-test-admin-token-unique":
                raise HTTPException(401, "Invalid test session")
            return "unit-test-admin"
        api_module.require_roles = test_require_roles
        cls.client = TestClient(app)
        cls.headers = {"Authorization": "Bearer unit-test-admin-token-unique"}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_cve_sync_rejects_overlapping_runs(self):
        from app.main import _CVE_SYNC_LOCK, run_cve_sync
        self.assertTrue(_CVE_SYNC_LOCK.acquire(blocking=False))
        try:
            result = run_cve_sync()
        finally:
            _CVE_SYNC_LOCK.release()
        self.assertTrue(result["busy"])

    def test_agent_tokens_are_stored_as_hashes(self):
        import hashlib
        from fastapi import HTTPException
        from app.main import conn, require_agent

        raw_token = "agent-secret-for-hash-test"
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        with conn() as c:
            c.execute("INSERT INTO agent_tokens(token,asset_id) VALUES(?,?)", (digest, "asset-hash-test"))

        self.assertEqual(require_agent("Bearer " + raw_token), "asset-hash-test")
        with self.assertRaises(HTTPException):
            require_agent("Bearer " + digest)

    def test_readiness_reports_database_state(self):
        response = self.client.get("/api/health/ready")
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.json()["checks"]["database"], {"ok", "error"})
        self.assertIn("cve_worker", response.json()["checks"])

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


    def test_hypervisor_provider_status(self):
        from unittest.mock import patch
        with patch("app.main.configured_providers", return_value=[
            {"provider":"vmware","configured":False,"mode":"read-only"},
            {"provider":"proxmox","configured":True,"mode":"read-only"},
        ]):
            response = self.client.get("/api/hypervisors/providers", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[1]["provider"], "proxmox")

    def test_hypervisor_inventory_reads_from_supabase_soc(self):
        from unittest.mock import patch
        rows = [{"provider":"proxmox","vm_id":"100","name":"soc-lab","state":"running",
                 "metadata":{"node":"pve01"},"last_seen":"2026-11-11T00:00:00Z","updated_by":"analyst"}]
        with patch("app.main.supabase_soc_request", return_value=rows) as request:
            response = self.client.get("/api/hypervisors/inventory", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["vm_id"], "100")
        request.assert_called_once()

    def test_hypervisor_sync_isolated_per_provider_and_upserts_to_supabase(self):
        from unittest.mock import patch
        providers = [
            {"provider":"proxmox","configured":True,"mode":"read-only"},
            {"provider":"vmware","configured":False,"mode":"read-only"},
        ]
        machines = [{"provider":"proxmox","id":"100","name":"soc-lab","state":"running",
                     "read_only":True,"metadata":{"node":"pve01"}}]
        with patch("app.main.configured_providers", return_value=providers), \
             patch("app.main.collect_hypervisor_inventory", return_value=machines), \
             patch("app.main.supabase_soc_request", return_value=[{"vm_id":"100"}]) as request:
            response = self.client.post("/api/hypervisors/sync", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["results"][0]["status"], "ok")
        self.assertEqual(response.json()["results"][1]["status"], "not-configured")
        self.assertEqual(request.call_args.args[0], "hypervisor_inventory?on_conflict=provider,vm_id")

if __name__ == "__main__":
    unittest.main()
