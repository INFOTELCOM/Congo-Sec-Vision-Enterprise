import json
import unittest
from unittest.mock import patch

from app import opencve


class _Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


class OpenCVEClientTests(unittest.TestCase):
    @patch.dict("os.environ", {
        "OPENCVE_API_TOKEN": "opc_org.test.secret",
        "OPENCVE_API_BASE_URL": "https://app.opencve.io/api/v2/",
    })
    @patch("app.opencve.urllib.request.urlopen")
    def test_search_uses_v2_bearer_and_advanced_query(self, urlopen):
        urlopen.return_value = _Response({"count": 1, "results": [
            {"cve_id": "CVE-2026-12345", "title": "Example"}
        ]})
        result = opencve.search_cves("vendor:microsoft AND cvss31>=9", page=2, page_size=100)
        self.assertEqual(result["count"], 1)
        request = urlopen.call_args.args[0]
        self.assertIn("/api/v2/cves?q=vendor%3Amicrosoft", request.full_url)
        self.assertEqual(request.get_header("Authorization"), "Bearer opc_org.test.secret")
        self.assertIn("page_size=100", request.full_url)

    @patch.dict("os.environ", {"OPENCVE_API_TOKEN": ""}, clear=False)
    def test_connection_reports_missing_token_without_network(self):
        self.assertEqual(opencve.check_connection(), {
            "configured": False,
            "connected": False,
            "base_url": opencve.DEFAULT_BASE_URL,
        })

    @patch.dict("os.environ", {"OPENCVE_API_TOKEN": "opc_org.test.secret"}, clear=False)
    @patch("app.opencve.urllib.request.urlopen")
    def test_connection_checks_catalog_endpoint(self, urlopen):
        urlopen.return_value = _Response({"count": 125, "results": []})
        result = opencve.check_connection()
        self.assertTrue(result["connected"])
        self.assertEqual(result["catalog_count"], 125)

    def test_cve_detail_rejects_invalid_identifiers(self):
        with self.assertRaises(opencve.OpenCVEError):
            opencve.get_cve("not-a-cve")

    @patch.dict("os.environ", {"OPENCVE_API_TOKEN": "opc_org.test.secret"}, clear=False)
    @patch("app.opencve.urllib.request.urlopen")
    def test_change_history_uses_cve_changes_endpoint(self, urlopen):
        urlopen.return_value = _Response({"count": 0, "results": []})
        result = opencve.get_cve_changes("CVE-2026-12345")
        self.assertEqual(result["count"], 0)
        self.assertIn("/cves/CVE-2026-12345/changes", urlopen.call_args.args[0].full_url)


if __name__ == "__main__":
    unittest.main()
