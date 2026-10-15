#!/usr/bin/env python3
"""Detect which technology stacks a project uses, from stacks/stacks.json.

Detection is deterministic (dependency names, file paths, content patterns), so
the auditors do not have to guess which playbooks apply.

    python3 detect_stacks.py [--root .] [--out .consultant/facts/stacks.json]

Standard library only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_packages  # noqa: E402  (reuse manifest parsing)

REGISTRY = Path(__file__).resolve().parent.parent / "stacks" / "stacks.json"
MAX_FILE_BYTES = 1_000_000
MAX_EVIDENCE = 5


def expand_braces(pattern: str) -> list[str]:
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out = []
    for alt in m.group(1).split(","):
        out.extend(expand_braces(pattern[: m.start()] + alt + pattern[m.end():]))
    return out


def matches(rel: str, patterns: list[str]) -> bool:
    # fnmatch's '*' already crosses '/', so '**/x' also needs to match a top-level 'x'
    for p in patterns:
        for q in {p, p.replace("**/", "")}:
            if fnmatch.fnmatch(rel, q):
                return True
    return False


def list_files(root: Path) -> list[str]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in verify_packages.SKIP_DIRS]
        for name in filenames:
            files.append((Path(dirpath) / name).relative_to(root).as_posix())
    return sorted(files)


def detect(root: Path, registry: dict) -> dict:
    files = list_files(root)
    deps = {p["name"].lower() for p in verify_packages.collect(root)}
    detected = []
    for stack in registry["stacks"]:
        rules = stack["detect"]
        evidence: list[str] = []
        for dep in rules.get("dependencies", []):
            if dep.lower() in deps:
                evidence.append(f"dependency: {dep}")
        for entry in rules.get("files", []):
            if any(c in entry for c in "*?["):
                hits = [f for f in files if matches(f, expand_braces(entry))]
                evidence += [f"file: {h}" for h in hits[:2]]
            elif (root / entry).exists():
                evidence.append(f"path: {entry}")
        for rule in rules.get("contains", []):
            globs, rx = expand_braces(rule["glob"]), re.compile(rule["pattern"])
            for f in files:
                if not matches(f, globs):
                    continue
                full = root / f
                try:
                    if full.stat().st_size > MAX_FILE_BYTES:
                        continue
                    if rx.search(full.read_text(encoding="utf-8", errors="ignore")):
                        evidence.append(f"content match in {f}")
                        break
                except OSError:
                    continue
        if evidence:
            detected.append({"id": stack["id"], "title": stack["title"], "playbook": stack["playbook"],
                             "evidence": evidence[:MAX_EVIDENCE]})
    return {"root": str(root), "detected": detected, "files_scanned": len(files)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--registry", default=REGISTRY, type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    result = detect(args.root.resolve(), json.loads(args.registry.read_text(encoding="utf-8")))
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print("detected: " + (", ".join(d["id"] for d in result["detected"]) or "none"), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
