import tempfile
import unittest
from pathlib import Path

from keylens.scanner import mask, scan_path


class ScannerTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask("abcdefgh"), "********")
        self.assertEqual(mask("ghp_1234567890abcdef"), "ghp_...cdef")

    def test_finds_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text(
                'TOKEN = "ghp_' + "a" * 36 + '"\n',
                encoding="utf-8",
            )
            findings, scanned = scan_path(root)
            self.assertEqual(scanned, 1)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].pattern, "GitHub PAT (classic)")
            self.assertEqual(findings[0].line, 1)
            self.assertIn("...", findings[0].match)

    def test_clean_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            findings, _ = scan_path(root)
            self.assertEqual(findings, [])

    def test_exclude_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ignored = root / "node_modules"
            ignored.mkdir()
            (ignored / "key.js").write_text("ghp_" + "b" * 36, encoding="utf-8")
            findings, scanned = scan_path(root)
            self.assertEqual(findings, [])
            self.assertEqual(scanned, 0)


if __name__ == "__main__":
    unittest.main()
