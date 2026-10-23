"""Baseline round-trip and CLI exit-code tests."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from skillshield import baseline as baseline_mod
from skillshield import scanner

FIXTURES = Path(__file__).parent / "fixtures"
MALICIOUS = FIXTURES / "malicious_skill"
CLEAN = FIXTURES / "clean_skill"
PROJECT_ROOT = Path(__file__).parent.parent


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "skillshield", *args],
        capture_output=True, text=True, cwd=PROJECT_ROOT,
    )


class TestBaseline(unittest.TestCase):
    def test_round_trip_suppresses_everything(self):
        result = scanner.scan_directory(MALICIOUS)
        self.assertTrue(result.findings)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            baseline_mod.write_baseline(result, path)
            fps = baseline_mod.load_baseline(path)
        self.assertEqual(len(fps), len(result.findings))

        fresh = scanner.scan_directory(MALICIOUS)
        baseline_mod.apply_baseline(fresh, fps)
        self.assertEqual(fresh.findings, [])
        self.assertEqual(len(fresh.suppressed), len(result.findings))

    def test_accepts_plain_list_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text(json.dumps(["abc123"]), encoding="utf-8")
            self.assertEqual(baseline_mod.load_baseline(path), {"abc123"})

    def test_invalid_json_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                baseline_mod.load_baseline(path)

    def test_unexpected_shape_raises_valueerror(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text(json.dumps({"wrong": 1}), encoding="utf-8")
            with self.assertRaises(ValueError):
                baseline_mod.load_baseline(path)

    def test_fingerprint_stable_across_line_shift(self):
        r1 = scanner.scan_directory(MALICIOUS)
        f1 = {f.fingerprint for f in r1.findings}
        r2 = scanner.scan_directory(MALICIOUS)
        f2 = {f.fingerprint for f in r2.findings}
        self.assertEqual(f1, f2)


class TestCli(unittest.TestCase):
    def test_malicious_fails_default_threshold(self):
        proc = run_cli(str(MALICIOUS))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("SS-DESTRUCT-001", proc.stdout)
        self.assertIn("FAIL", proc.stdout)

    def test_critical_threshold_still_fails_on_destructive(self):
        proc = run_cli(str(MALICIOUS), "--fail-on", "critical")
        self.assertEqual(proc.returncode, 1)

    def test_clean_passes(self):
        proc = run_cli(str(CLEAN))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)

    def test_json_output_is_valid(self):
        proc = run_cli(str(MALICIOUS), "--format", "json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["tool"], "skillshield")
        self.assertEqual(payload["verdict"], "fail")
        self.assertTrue(payload["findings"])
        for f in payload["findings"]:
            for key in ("rule_id", "severity", "path", "line", "evidence",
                        "remediation", "fingerprint"):
                self.assertIn(key, f)

    def test_missing_target_is_usage_error(self):
        proc = run_cli(str(FIXTURES / "nope"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr.lower())

    def test_write_baseline_then_scan_with_it_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bpath = str(Path(tmp) / "baseline.json")
            proc = run_cli(str(MALICIOUS), "--write-baseline", bpath)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            proc = run_cli(str(MALICIOUS), "--baseline", bpath)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("suppressed", proc.stdout)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            proc = run_cli(str(CLEAN), "--format", "json", "-o", str(out))
            self.assertEqual(proc.returncode, 0)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["verdict"], "pass")

    def test_non_ascii_evidence_does_not_crash_narrow_console(self):
        # A flagged line containing characters outside the console codepage
        # (e.g. GBK on Windows) must still print a report, not a traceback.
        import os
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "evil.sh").write_text(
                "#!/bin/bash\nrm -rf ~/  # \U0001f525\n", encoding="utf-8")
            env = dict(os.environ, PYTHONIOENCODING="gbk")
            proc = subprocess.run(
                [sys.executable, "-m", "skillshield", tmp],
                capture_output=True, text=True, cwd=PROJECT_ROOT, env=env,
                encoding="gbk", errors="replace")
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertIn("SS-DESTRUCT-001", proc.stdout)


if __name__ == "__main__":
    unittest.main()
