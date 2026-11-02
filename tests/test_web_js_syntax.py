"""Regression checks for inline JavaScript embedded in the web consoles."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HTML_FILES = (ROOT / "web" / "index.html", ROOT / "app" / "static" / "index.html")


class InlineJavaScriptSyntaxTests(unittest.TestCase):
    def test_inline_scripts_parse_with_node(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is required for JavaScript syntax checks")

        for html_file in HTML_FILES:
            if not html_file.exists():
                continue
            source = html_file.read_text(encoding="utf-8")
            scripts = re.findall(
                r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script\s*>",
                source,
                flags=re.IGNORECASE | re.DOTALL,
            )
            for index, script in enumerate(scripts, start=1):
                if not script.strip():
                    continue
                with self.subTest(file=html_file.relative_to(ROOT), script=index):
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".js", encoding="utf-8", delete=False
                    ) as temp:
                        temp.write(script)
                        temp_path = Path(temp.name)
                    try:
                        result = subprocess.run(
                            [node, "--check", str(temp_path)],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.assertEqual(
                            result.returncode,
                            0,
                            msg=result.stderr or result.stdout,
                        )
                    finally:
                        temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
