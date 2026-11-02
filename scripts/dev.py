#!/usr/bin/env python3
"""One command that runs exactly what CI runs, on Linux, macOS and Windows.

    python scripts/dev.py check     # the same checks as .github/workflows/ci.yml
    python scripts/dev.py build     # regenerate checklist/checklist.json

Why this exists: the important checks are several commands, and a contributor on
Windows should not have to discover that the console code page matters. This runs
the child processes with PYTHONUTF8=1 and reports every failure, not just the first.

Requires Python 3.11+ and, for `build` and the checklist-authoring tests, PyYAML.
Unit tests that need PyYAML skip themselves when it is missing, which matches what
a plain `python -m unittest discover -s tests` does.

Standard library only.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = {**os.environ, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1"}
PY = sys.executable
SAMPLE_DATE = "2026-10-15"          # keeps examples/sample-output/REPORT.md reproducible


def check_sample_report() -> int:
    """Render a copy, so a check run never dirties the working tree.

    examples/sample-output is a committed artefact. Rendering in place would rewrite it
    (and create state.json) on every check, hiding whether the committed copy is current.
    """
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        dst = Path(tmp) / "sample-output"
        shutil.copytree(ROOT / "examples" / "sample-output", dst)
        return run([PY, "scripts/render_report.py", "--dir", str(dst), "--today", SAMPLE_DATE])


def check_manifest_json() -> int:
    """The plugin manifests are read by Claude Code before any Python runs."""
    import json
    for name in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"):
        try:
            json.loads((ROOT / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"invalid {name}: {exc}", file=sys.stderr)
            return 1
    return 0


def check_steps() -> list[tuple[str, Callable[[], int]]]:
    return [
        ("checklist schema", lambda: run([PY, "scripts/checklist.py", "validate"])),
        ("generated checklist.json is fresh", lambda: run([PY, "scripts/checklist.py", "build", "--check"])),
        ("unit tests", lambda: run([PY, "-m", "unittest", "discover", "-s", "tests"])),
        ("sample report renders", check_sample_report),
        ("plugin manifests are valid JSON", check_manifest_json),
    ]


def run(cmd: list[str]) -> int:
    print("$ " + " ".join(cmd[1:]), flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=ENV).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=("check", "build"), nargs="?", default="check")
    args = ap.parse_args()

    if args.action == "build":
        return run([PY, "scripts/checklist.py", "build"])

    failed = []
    for name, step in check_steps():
        print(f"\n== {name} ==", flush=True)
        code = step()
        if code != 0:
            failed.append(name)
            print(f"-- {name} FAILED (exit {code})", file=sys.stderr, flush=True)

    if failed:
        print("\nFailed: " + ", ".join(failed), file=sys.stderr)
        print("Fix these before opening a pull request.", file=sys.stderr)
        return 1
    print("\nOK: every check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
