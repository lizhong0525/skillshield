"""True-positive and false-positive fixture tests for the scanner."""

import unittest
from pathlib import Path

from skillshield import scanner

FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "malicious_skill"
CLEAN = FIXTURES / "clean_skill"


def rule_ids(result):
    return {f.rule_id for f in result.findings}


class TestMaliciousFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scanner.scan_directory(MALICIOUS)

    def test_all_core_rules_fire(self):
        ids = rule_ids(self.result)
        for expected in ("SS-DESTRUCT-001", "SS-CREDS-001", "SS-NET-001",
                         "SS-PERM-001", "SS-OBFUSC-001", "SS-PROMPT-001",
                         "SS-META-001"):
            self.assertIn(expected, ids)

    def test_finding_fields_are_complete(self):
        for f in self.result.findings:
            self.assertTrue(f.rule_id.startswith("SS-"))
            self.assertTrue(f.severity)
            self.assertTrue(f.remediation)
            self.assertTrue(f.fingerprint)
            if f.path != ".":
                self.assertGreaterEqual(f.line, 1)
                self.assertTrue(f.evidence)

    def test_precise_locations(self):
        by_rule = {}
        for f in self.result.findings:
            by_rule.setdefault((f.rule_id, f.path), f)
        destruct = by_rule[("SS-DESTRUCT-001", "setup.sh")]
        # `rm -rf ~/` is line 7 of setup.sh
        self.assertEqual(destruct.line, 7)
        self.assertIn("rm -rf ~/", destruct.evidence)

    def test_no_errors_on_fixture(self):
        self.assertEqual(self.result.errors, [])

    def test_breach_threshold(self):
        self.assertTrue(self.result.breaches("high"))
        self.assertTrue(self.result.breaches("critical"))


class TestCleanFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scanner.scan_directory(CLEAN)

    def test_no_findings(self):
        self.assertEqual(self.result.findings, [])

    def test_files_were_scanned(self):
        self.assertGreaterEqual(self.result.files_scanned, 3)

    def test_no_breach_at_any_threshold(self):
        self.assertFalse(self.result.breaches("info"))


class TestScannerRobustness(unittest.TestCase):
    def test_missing_directory_raises(self):
        with self.assertRaises(FileNotFoundError):
            scanner.scan_directory(FIXTURES / "does-not-exist")

    def test_file_as_root_raises(self):
        with self.assertRaises(NotADirectoryError):
            scanner.scan_directory(CLEAN / "SKILL.md")

    def test_binary_and_invalid_utf8_are_skipped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "blob.py").write_bytes(b"\x00\x01\x02binary\xff\xfe")
            (root / "bad.sh").write_bytes(b"echo ok \xff\xfe\n")
            result = scanner.scan_directory(root)
            # no crash; binary file reported as skipped, invalid-utf8 tolerated
            self.assertTrue(any("blob.py" in e for e in result.errors))

    def test_empty_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = scanner.scan_directory(tmp)
            self.assertEqual(result.files_scanned, 0)
            ids = rule_ids(result)
            self.assertIn("SS-META-001", ids)  # no LICENSE anywhere
            self.assertNotIn("SS-META-002", ids)  # no docs to judge


if __name__ == "__main__":
    unittest.main()
