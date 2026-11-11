import unittest
from unittest.mock import patch

from app.cve_engine import (
    _applies, _version_compare, _severity, _extract_weaknesses,
    search_nvd, scan_product,
)


def cve_with(node):
    return {"configurations": [{"nodes": [node]}]}


class CveApplicabilityTests(unittest.TestCase):
    def test_version_range_match(self):
        cve = cve_with({"operator": "OR", "cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.0", "versionEndExcluding": "3.0"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", "2.5"), "version-range-match")

    def test_version_outside_range_is_candidate(self):
        cve = cve_with({"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.0", "versionEndExcluding": "3.0"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", "3.1"), "candidate")

    def test_unknown_version_is_never_confirmed(self):
        cve = cve_with({"cpeMatch": [{
            "vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", ""), "candidate")

    def test_numeric_versions_are_compared_naturally(self):
        self.assertEqual(_version_compare("1.10", "1.9"), 1)
        self.assertEqual(_version_compare("2.0.0", "2"), 0)

    def test_and_node_requires_every_child(self):
        cve = cve_with({"operator": "AND", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:other:*:*:*:*:*:*:*:*"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", "2.0"), "candidate")

    def test_negated_node_does_not_match(self):
        cve = cve_with({"operator": "OR", "negate": True, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", "2.0"), "candidate")

    def test_non_vulnerable_cpe_is_ignored(self):
        cve = cve_with({"cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]})
        self.assertEqual(_applies(cve, "Widget", "Acme", "2.0"), "candidate")

    def test_cvss_and_cwe_are_extracted(self):
        cve = {
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        }
        self.assertEqual(_severity(cve)[:3], ("critical", 9.8, "3.1"))
        self.assertEqual(_extract_weaknesses(cve), ["CWE-79"])


class NvdPaginationTests(unittest.TestCase):
    @patch("app.cve_engine.time.sleep")
    @patch("app.cve_engine._request_json")
    def test_search_nvd_fetches_all_pages(self, request, _sleep):
        request.side_effect = [
            {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2025-0001"}},
                                                        {"cve": {"id": "CVE-2025-0002"}}]},
            {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "CVE-2025-0003"}}]},
        ]
        result = search_nvd("acme widget", results_per_page=2)
        self.assertEqual(len(result["vulnerabilities"]), 3)
        self.assertEqual(result["pagesFetched"], 2)
        self.assertFalse(result["truncated"])
        self.assertEqual(request.call_count, 2)

    @patch("app.cve_engine._kev_ids", return_value=frozenset({"CVE-2025-0001"}))
    @patch("app.cve_engine._epss_for", return_value={"CVE-2025-0001": {"score": 0.72, "percentile": 0.98}})
    @patch("app.cve_engine.search_nvd")
    def test_scan_enriches_cve_without_claiming_exposure(self, search, _epss, _kev):
        search.return_value = {"vulnerabilities": [{"cve": {
            "id": "CVE-2025-0001",
            "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
            "references": [{"url": "https://vendor.example/security", "tags": ["Vendor Advisory"]}],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "2.0", "versionEndExcluding": "3.0"}]}]}],
        }}]}
        row = scan_product("Widget", "2.5", "Acme")[0]
        self.assertEqual(row["cvss_score"], 9.8)
        self.assertEqual(row["epss_score"], 0.72)
        self.assertTrue(row["known_exploited"])
        self.assertEqual(row["match_confidence"], "version-range-match")
        self.assertIn("CWE-79", row["cwe_ids"])
        self.assertEqual(row["references"][0]["tags"], ["Vendor Advisory"])


if __name__ == "__main__":
    unittest.main()
