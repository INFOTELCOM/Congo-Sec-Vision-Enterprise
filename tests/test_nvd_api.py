import unittest
from unittest.mock import patch

from app import cve_engine


class NvdInteractiveApiTests(unittest.TestCase):
    @patch("app.cve_engine._request_json")
    def test_catalog_search_paginates_and_uses_keyword_search(self, request):
        request.return_value = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}]}
        result = cve_engine.search_nvd_catalog(
            keyword="microsoft windows", page=2, page_size=25, api_key="nvd-test-key"
        )
        url = request.call_args.args[0]
        self.assertIn("keywordSearch=microsoft", url)
        self.assertIn("startIndex=25", url)
        self.assertEqual(request.call_args.kwargs["api_key"], "nvd-test-key")
        self.assertEqual(result["totalResults"], 1)

    @patch("app.cve_engine._request_json")
    def test_catalog_search_accepts_cve_id_and_kev_filter(self, request):
        request.return_value = {"totalResults": 1, "vulnerabilities": []}
        cve_engine.search_nvd_catalog(cve_id="CVE-2026-12345", has_kev=True)
        url = request.call_args.args[0]
        self.assertIn("cveId=CVE-2026-12345", url)
        self.assertIn("hasKev=true", url)

    def test_catalog_search_rejects_bad_cve_identifier(self):
        with self.assertRaises(ValueError):
            cve_engine.search_nvd_catalog(cve_id="not-a-cve")

    @patch("app.cve_engine._request_json")
    def test_detail_returns_cve_record_not_envelope(self, request):
        request.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}]}
        result = cve_engine.get_nvd_cve("cve-2026-12345")
        self.assertEqual(result["id"], "CVE-2026-12345")
        self.assertIn("cveId=CVE-2026-12345", request.call_args.args[0])

    @patch("app.cve_engine._request_json")
    def test_history_uses_cve_history_2_endpoint(self, request):
        request.return_value = {"totalResults": 0, "cveChanges": []}
        cve_engine.get_nvd_cve_history("CVE-2026-12345", page=2, page_size=10)
        url = request.call_args.args[0]
        self.assertIn("/cvehistory/2.0?", url)
        self.assertIn("cveId=CVE-2026-12345", url)
        self.assertIn("startIndex=10", url)

    @patch("app.cve_engine._request_json")
    def test_cpe_search_uses_official_dictionary_api(self, request):
        request.return_value = {"totalResults": 0, "products": []}
        cve_engine.search_nvd_cpes("Microsoft Windows")
        self.assertIn("/cpes/2.0?", request.call_args.args[0])
        self.assertIn("keywordSearch=Microsoft", request.call_args.args[0])

    @patch("app.cve_engine._request_json")
    def test_cpe_match_search_uses_cve_id_endpoint(self, request):
        request.return_value = {"totalResults": 0, "matchStrings": []}
        cve_engine.search_nvd_cpe_matches("CVE-2026-12345")
        self.assertIn("/cpematch/2.0?", request.call_args.args[0])
        self.assertIn("cveId=CVE-2026-12345", request.call_args.args[0])

    def test_cpe_match_search_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            cve_engine.search_nvd_cpe_matches("apache http server")


if __name__ == "__main__":
    unittest.main()
