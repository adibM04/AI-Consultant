#!/usr/bin/env python3
"""Record, list or remove a founder's attestation in .consultant/attestations.json.

An attestation is a person's signed statement that something the code cannot show is true
("I restored last night's backup to staging on 2026-09-20 and it took 14 minutes"), backed by an
evidence document in the repository. It can settle items the repository cannot prove. It can never
override a failing code finding, and it expires within a year.

    python3 attest.py add --item DAT-08 --by "Jane Doe" --note "Restored nightly backup to staging, 14 min" \\
                          --evidence docs/evidence/restore-2026-09.md [--valid-days 365]
    python3 attest.py list
    python3 attest.py remove --item DAT-08

Refuses: items that are checkable in code, evidence files that do not exist or look like they
contain secrets, and anything the report renderer would reject. Secret VALUES are never printed.
Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_report as rr  # noqa: E402

SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "Stripe live key": r"\b[sr]k_live_[0-9a-zA-Z]{10,}",
    "private key block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "GitHub token": r"\bgh[pousr]_[0-9A-Za-z]{30,}",
    "Slack token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}",
    "Google API key": r"\bAIza[0-9A-Za-z_-]{30,}",
    "JSON web token": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "password assignment": r"(?i)\bpass(?:word|wd)?\s*[:=]\s*['\"]?[^\s'\"]{6,}",
    "connection string with credentials": r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@",
}
MAX_SCAN_BYTES = 2_000_000


def scan_for_secrets(path: Path) -> tuple[list[str], bool]:
    """Return (kinds of secret found, was_scanned). Never returns the matched text."""
    try:
        data = path.read_bytes()
    except OSError:
        return [], False
    if len(data) > MAX_SCAN_BYTES or b"\0" in data[:4096]:
        return [], False  # binary or huge: cannot scan
    text = data.decode("utf-8", errors="ignore")
    return [kind for kind, rx in SECRET_PATTERNS.items() if re.search(rx, text)], True


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def cmd_add(args, today: dt.date) -> int:
    root, audit = args.root.resolve(), args.dir
    st = rr.load_state(audit, root, today=today)
    items = {i["id"]: i for d in st["checklist"]["domains"] for i in d["items"]}
    item = items.get(args.item)
    if item is None:
        print(f"error: unknown checklist item {args.item}", file=sys.stderr)
        return 2
    row = next(r for r in st["rows"] if r["id"] == args.item)
    if row["state"] in {"fail", "partial"}:
        print(f"error: the code audit says {args.item} is {row['state']}. Fix it and re-audit; a statement cannot override that.", file=sys.stderr)
        return 2

    warnings = []
    for ref in args.evidence:
        if not rr.evidence_resolves(ref, root):
            print(f"error: evidence file not found inside the project (or under .consultant/): {ref}", file=sys.stderr)
            return 2
        found, scanned = scan_for_secrets(root / ref.split(":")[0])
        if found:
            print(f"error: {ref} looks like it contains secrets ({', '.join(found)}). Redact them first: an evidence "
                  f"file is committed to git and read by reviewers and AI tools.", file=sys.stderr)
            return 2
        if not scanned:
            warnings.append(f"{ref} is binary or large and was not scanned for secrets: check it by eye before committing")

    entry = {"attested_by": args.by.strip(), "date": today.isoformat(),
             "expires": (today + dt.timedelta(days=args.valid_days)).isoformat(),
             "note": args.note.strip(), "evidence": args.evidence}
    candidate = {args.item: entry}
    _, _, rejected = rr.active_attestations(candidate, today, items, root)
    if rejected:
        print(f"error: {args.item} rejected: {rejected[args.item]}", file=sys.stderr)
        return 2

    path = audit / "attestations.json"
    existing = load(path)
    replaced = args.item in existing
    existing[args.item] = entry
    audit.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{'Updated' if replaced else 'Recorded'} attestation for {args.item} ({item['title'][:70]}), valid until {entry['expires']}.")
    for w in warnings:
        print(f"warning: {w}")
    print("Re-render the report: python3 scripts/render_report.py --dir .consultant")
    return 0


def cmd_list(args, today: dt.date) -> int:
    st = rr.load_state(args.dir, args.root.resolve(), today=today)
    rows = {r["id"]: r for r in st["rows"]}
    for iid, a in sorted(st["attestations"].items()):
        print(f"active   {iid}  by {a['attested_by']}  until {a['expires']}  {rows[iid]['title'][:60]}")
    for iid, a in sorted(st["attest_expired"].items()):
        print(f"EXPIRED  {iid}  by {a['attested_by']}  expired {a['expires']}")
    for iid, why in sorted(st["attest_rejected"].items()):
        print(f"REJECTED {iid}  {why}")
    if not (st["attestations"] or st["attest_expired"] or st["attest_rejected"]):
        print("no attestations")
    return 0


def cmd_remove(args, today: dt.date) -> int:
    path = args.dir / "attestations.json"
    existing = load(path)
    if args.item not in existing:
        print(f"no attestation for {args.item}")
        return 1
    del existing[args.item]
    path.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Removed attestation for {args.item}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".consultant", type=Path)
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--today", help="override date (YYYY-MM-DD), for tests")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--item", required=True)
    a.add_argument("--by", required=True, help="the person making the statement")
    a.add_argument("--note", required=True, help="what was done and when, in one or two sentences")
    a.add_argument("--evidence", required=True, nargs="+", help="path(s) of evidence file(s) in the project")
    a.add_argument("--valid-days", type=int, default=rr.ATTEST_MAX_DAYS)
    sub.add_parser("list")
    r = sub.add_parser("remove")
    r.add_argument("--item", required=True)
    args = ap.parse_args()
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    return {"add": cmd_add, "list": cmd_list, "remove": cmd_remove}[args.cmd](args, today)


if __name__ == "__main__":
    sys.exit(main())
