"""Command-line interface for SkillShield."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, baseline as baseline_mod, report, scanner
from .models import SEVERITIES, severity_rank

EXIT_PASS = 0
EXIT_THRESHOLD_BREACH = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillshield",
        description="Static security scanner for AI-agent skill folders. "
                    "Reads files only - never executes scanned code.",
    )
    p.add_argument("target", help="path to the skill directory to scan")
    p.add_argument("--format", choices=("text", "json"), default="text",
                   help="output format (default: text)")
    p.add_argument("--output", "-o", metavar="PATH",
                   help="write the report to PATH instead of stdout")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   metavar="SEVERITY",
                   help="exit with code 1 if any finding is at or above this "
                        "severity (default: high). Use 'critical' to only fail "
                        "on the worst issues.")
    p.add_argument("--baseline", metavar="PATH",
                   help="JSON baseline file with fingerprints of accepted "
                        "findings to suppress")
    p.add_argument("--write-baseline", metavar="PATH",
                   help="write all current findings to PATH as a baseline file "
                        "and exit 0 (use to adopt existing findings)")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    # Consoles with a narrow codepage (e.g. GBK on Windows) must not crash on
    # non-ASCII evidence: fall back to replacement characters when printing.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

    args = build_parser().parse_args(argv)

    try:
        result = scanner.scan_directory(args.target)
    except (FileNotFoundError, NotADirectoryError, PermissionError) as exc:
        print(f"skillshield: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.baseline:
        try:
            fps = baseline_mod.load_baseline(args.baseline)
        except (ValueError, OSError) as exc:
            print(f"skillshield: error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        baseline_mod.apply_baseline(result, fps)

    if args.write_baseline:
        try:
            baseline_mod.write_baseline(result, args.write_baseline)
        except OSError as exc:
            print(f"skillshield: error: cannot write baseline: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Baseline with {len(result.findings)} finding(s) written to "
              f"{args.write_baseline}")
        return EXIT_PASS

    text = (report.render_json if args.format == "json"
            else report.render_text)(result, args.fail_on)
    if args.output:
        try:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"skillshield: error: cannot write report: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        print(text)

    return EXIT_THRESHOLD_BREACH if result.breaches(args.fail_on) else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
