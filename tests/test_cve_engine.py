import unittest
from app.cve_engine import _applies

class CveEngineTests(unittest.TestCase):
    def test_version_range_match_is_flagged(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"3.0"}]}]}]}
        self.assertEqual(_applies(cve,"Widget","Acme","2.5"),"version-range-match")

    def test_outside_version_range_remains_candidate(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"3.0"}]}]}]}
        self.assertEqual(_applies(cve,"Widget","Acme","3.1"),"candidate")

    def test_unknown_version_is_not_confirmed(self):
        cve={"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}]}]}]}
        self.assertEqual(_applies(cve,"Widget","Acme",""),"candidate")

if __name__ == "__main__": unittest.main()