import re
import unittest
from pathlib import Path


class DashboardInteractionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = Path("app/static/index.html").read_text(encoding="utf-8")

    def test_inline_event_handlers_have_implemented_functions(self):
        handlers = re.findall(
            r'\bon(?:click|submit|change|keydown)\s*=\s*"([^"]+)"',
            self.html,
        )
        referenced = set()
        for expression in handlers:
            match = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\(", expression)
            if match and match.group(1) != "if":
                referenced.add(match.group(1))

        declared = set(re.findall(
            r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(",
            self.html,
        ))
        self.assertTrue(referenced, "No dashboard event handlers were found.")
        self.assertEqual(
            referenced - declared,
            set(),
            "Every inline dashboard button/input handler must resolve to a function.",
        )

    def test_all_html_ids_are_unique(self):
        ids = re.findall(r'id="([^"]+)"', self.html)
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        self.assertEqual(
            duplicates,
            [],
            "HTML element IDs must be unique; duplicate IDs can break page navigation.",
        )

    def test_navigation_targets_have_matching_dashboard_sections(self):
        targets = set(re.findall(r'data-page="([a-z0-9_-]+)"', self.html))
        sections = set(re.findall(
            r'<section\b[^>]*\bid="([a-z0-9_-]+)"[^>]*class="page',
            self.html,
        ))
        self.assertTrue(targets)
        self.assertEqual(targets - sections, set())


if __name__ == "__main__":
    unittest.main()
