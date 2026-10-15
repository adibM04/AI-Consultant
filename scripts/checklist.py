#!/usr/bin/env python3
"""Validate the YAML checklist and build checklist/checklist.json.

Usage:
    python3 scripts/checklist.py validate        # schema + uniqueness checks
    python3 scripts/checklist.py build           # write checklist/checklist.json
    python3 scripts/checklist.py build --check   # fail if the JSON is out of date

Needs PyYAML (contributors only). The generated JSON is committed so that
end users and the report renderer need nothing but the Python standard library.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST_DIR = ROOT / "checklist"
OUTPUT = CHECKLIST_DIR / "checklist.json"

SEVERITIES = ("critical", "high", "medium", "low")
EVIDENCE = ("code", "config", "process")
TIERS = (1, 2, 3)
TAGS = {
    "b2b", "enterprise", "multi-tenant", "payments", "cards", "subscriptions",
    "usage-billing", "pii", "phi", "eu", "ai", "api", "webhooks", "integrations",
    "email", "files", "i18n",
}
ROLES = {
    "senior-engineer", "backend-engineer", "frontend-engineer", "devops",
    "security", "compliance", "legal", "finance", "qa", "tech-lead", "architect",
}
ID_RE = re.compile(r"^[A-Z]{3}-\d{2}$")
ITEM_KEYS = {"id", "title", "severity", "tier", "when", "evidence", "role", "check"}


def load_domains() -> list[dict]:
    domains = []
    for path in sorted(CHECKLIST_DIR.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["_file"] = path.name
        domains.append(data)
    return domains


def validate(domains: list[dict]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_domains: set[str] = set()
    for d in domains:
        f = d["_file"]
        for key in ("domain", "title", "summary", "items"):
            if key not in d:
                errors.append(f"{f}: missing top-level key '{key}'")
        if not d.get("items"):
            errors.append(f"{f}: no items")
            continue
        if d["domain"] in seen_domains:
            errors.append(f"{f}: duplicate domain '{d['domain']}'")
        seen_domains.add(d["domain"])
        prefixes = set()
        for item in d["items"]:
            iid = item.get("id", "<no id>")
            where = f"{f}:{iid}"
            missing = ITEM_KEYS - item.keys()
            extra = item.keys() - ITEM_KEYS
            if missing:
                errors.append(f"{where}: missing keys {sorted(missing)}")
            if extra:
                errors.append(f"{where}: unknown keys {sorted(extra)}")
            if not ID_RE.match(str(iid)):
                errors.append(f"{where}: id must look like ABC-01")
            else:
                prefixes.add(iid.split("-")[0])
            if iid in seen_ids:
                errors.append(f"{where}: duplicate id")
            seen_ids.add(iid)
            if item.get("severity") not in SEVERITIES:
                errors.append(f"{where}: severity must be one of {SEVERITIES}")
            if item.get("tier") not in TIERS:
                errors.append(f"{where}: tier must be one of {TIERS}")
            if item.get("evidence") not in EVIDENCE:
                errors.append(f"{where}: evidence must be one of {EVIDENCE}")
            if item.get("role") not in ROLES:
                errors.append(f"{where}: unknown role '{item.get('role')}'")
            when = item.get("when")
            if not isinstance(when, list):
                errors.append(f"{where}: 'when' must be a list (use [] for always)")
            else:
                for tag in when:
                    if tag not in TAGS:
                        errors.append(f"{where}: unknown tag '{tag}'")
            for key in ("title", "check"):
                if not str(item.get(key, "")).strip():
                    errors.append(f"{where}: empty {key}")
        if len(prefixes) > 1:
            errors.append(f"{f}: mixed id prefixes {sorted(prefixes)}")
    return errors


def build(domains: list[dict]) -> dict:
    out_domains = []
    for d in domains:
        out_domains.append(
            {
                "domain": d["domain"],
                "title": d["title"],
                "summary": d["summary"],
                "file": f"checklist/{d['_file']}",
                "items": [dict(item) for item in d["items"]],
            }
        )
    return {
        "tags": sorted(TAGS),
        "roles": sorted(ROLES),
        "domains": out_domains,
    }


def render(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("validate", "build"))
    parser.add_argument("--check", action="store_true", help="with build: fail if stale")
    args = parser.parse_args()

    domains = load_domains()
    errors = validate(domains)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    total = sum(len(d["items"]) for d in domains)

    if args.command == "validate":
        print(f"OK: {len(domains)} domains, {total} items")
        return 0

    rendered = render(build(domains))
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print(
                "checklist/checklist.json is out of date. "
                "Run: python3 scripts/checklist.py build",
                file=sys.stderr,
            )
            return 1
        print("OK: checklist.json is up to date")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(domains)} domains, {total} items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
