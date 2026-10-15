#!/usr/bin/env python3
"""Draft answers to a buyer's security questionnaire from the audit, without overclaiming.

    python3 questionnaire.py match  --csv Q.csv [--column NAME] [--dir .consultant] [--root .] > candidates.json
    python3 questionnaire.py render --csv Q.csv --answers answers.json --out-csv draft.csv --out-md summary.md

`match` proposes checklist items for each question (keyword themes) and shows each item's current
state. A model then reads the questions and writes answers.json:

    [{"row": 1, "stance": "yes|partial|no|unknown|na", "items": ["SEC-12"], "answer": "..."}]

`render` is the honesty layer, enforced in code, not in the prompt:

  * A stance can never be stronger than the mapped items allow. "Yes" needs every in-scope item to
    be pass or attested; any fail/partial/unknown caps it. A question with no mapped item is
    "unknown". Out-of-scope items (later stage) count as unknown.
  * When a stance is lowered, the model's prose is DISCARDED and replaced with deterministic text
    built from the checklist titles, so the answer cannot contradict the evidence.
  * The Evidence and Basis columns are generated from audit data (finding evidence that resolves,
    attestations with who/when), never from model prose.
  * Cells are neutralised against spreadsheet formula injection. Every row is marked DRAFT.

Questionnaire text is untrusted input: it only ever selects rows and is never executed or obeyed.
Standard library only. XLSX is not supported: export the sheet to CSV first.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_report as rr  # noqa: E402

TOPICS = Path(__file__).resolve().parent.parent / "checklist" / "questionnaire-topics.json"
MAX_ROWS = 600
STALE_DAYS = 90
RANK = {"unknown": 0, "no": 1, "partial": 2, "yes": 3}
NEW_COLUMNS = ["Draft stance", "Draft answer", "Basis (checklist items)", "Evidence", "Needs from founder", "Flags"]
QUESTION_HINTS = ("question", "requirement", "control", "description", "query", "prompt")


# ---------------------------------------------------------------- csv

def read_csv(path: Path):
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(text.splitlines(), dialect))
    rows = [r for r in rows if any(c.strip() for c in r)]
    if len(rows) < 2:
        sys.exit("The CSV needs a header row and at least one question.")
    if len(rows) - 1 > MAX_ROWS:
        sys.exit(f"{len(rows) - 1} rows; the limit is {MAX_ROWS}. Split the questionnaire.")
    return rows[0], rows[1:], dialect


def question_column(header, rows, explicit=None) -> int:
    if explicit:
        for i, h in enumerate(header):
            if h.strip().lower() == explicit.strip().lower():
                return i
        sys.exit(f"column {explicit!r} not found. Columns: {header}")
    for hint in QUESTION_HINTS:
        for i, h in enumerate(header):
            if hint in h.lower():
                return i
    lengths = [sum(len(r[i]) if i < len(r) else 0 for r in rows) for i in range(len(header))]
    return max(range(len(header)), key=lambda i: lengths[i])


def neutralise(cell) -> str:
    s = str(cell)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


# ---------------------------------------------------------------- matching

def keyword_hit(text: str, kw: str) -> bool:
    if len(kw) <= 4 and " " not in kw:
        return re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", text) is not None
    return re.search(rf"(?<![a-z0-9]){re.escape(kw)}", text) is not None


def match_topics(question: str, topics: list[dict]) -> list[dict]:
    q = question.lower()
    hits = []
    for t in topics:
        n = sum(1 for kw in t["keywords"] if keyword_hit(q, kw))
        if n:
            hits.append((n, t))
    return [t for _, t in sorted(hits, key=lambda h: -h[0])]


# ---------------------------------------------------------------- honesty rules

def category(row: dict) -> str:
    """sat / fail / part / unk / na for one checklist row."""
    state = row["state"]
    if state == "waived":
        state = (row.get("finding") or {}).get("status", "unknown")
        state = state if state in ("fail", "partial") else "unknown"
    if state in ("pass", "attested"):
        return "sat"
    if state == "fail":
        return "fail"
    if state == "partial":
        return "part"
    if state == "na":
        return "na"    # only when an auditor judged it irrelevant and said why
    return "unk"       # unknown, unaudited, later, and not-applicable: "the audit did not assess it" is not "it does not apply to us"


def allowed_stance(cats: list[str]) -> str:
    if not cats:
        return "unknown"
    c = {k: cats.count(k) for k in ("sat", "fail", "part", "unk", "na")}
    if c["fail"] or c["part"]:
        return "partial" if (c["sat"] or c["part"]) else "no"
    if c["unk"]:
        return "unknown"
    return "yes" if c["sat"] else "na"


def cap_stance(requested: str, allowed: str) -> str:
    if requested == "na":
        return "na" if allowed == "na" else "unknown"
    if allowed == "na":
        return "na" if requested in ("na", "yes") else "unknown"
    return requested if RANK.get(requested, 0) <= RANK[allowed] else allowed


def safe_answer(stance: str, rows: list[dict]) -> str:
    """Deterministic wording built only from checklist titles and states."""
    by = {k: [r["title"] for r in rows if category(r) == k] for k in ("sat", "fail", "part", "unk")}
    if stance == "yes":
        return "Yes. " + "; ".join(by["sat"][:4]) + "."
    parts = []
    if by["sat"]:
        parts.append("In place: " + "; ".join(by["sat"][:3]))
    if by["part"]:
        parts.append("Partly in place: " + "; ".join(by["part"][:3]))
    if by["fail"]:
        parts.append("Not currently in place: " + "; ".join(by["fail"][:3]))
    if by["unk"]:
        parts.append("Not yet verified: " + "; ".join(by["unk"][:3]))
    if stance == "unknown" and not parts:
        return "To be confirmed by the company; this has not been verified."
    return ". ".join(parts) + "."


def evidence_cell(row: dict, root: Path) -> str:
    if row["state"] == "attested":
        a = row["attestation"]
        return f"{row['id']}: attested by {a.get('attested_by')} on {a.get('date')} (document: {', '.join(a.get('evidence', []))})"
    if row["state"] == "pass":
        refs = [e for e in (row.get("finding") or {}).get("evidence", []) if rr.evidence_resolves(e, root)]
        return f"{row['id']}: " + ", ".join(refs[:3]) if refs else ""
    return ""


def need_cell(row: dict, stage: str) -> str:
    state = row["state"]
    if state == "later":
        return f"{row['id']}: not assessed at stage '{stage}'. Re-run the audit at a higher stage to cover it."
    if state == "not-applicable":
        return f"{row['id']}: the audit profile does not include the tags this item needs, so it was not assessed. Add them and re-audit if the buyer needs an answer."
    if state in ("unknown", "unaudited"):
        q = (row.get("finding") or {}).get("question")
        return f"{row['id']}: {q or 'show evidence for: ' + row['check']}"
    return ""


# ---------------------------------------------------------------- commands

def load_everything(args, today):
    st = rr.load_state(args.dir, args.root.resolve(), today=today)
    rows = {r["id"]: r for r in st["rows"]}
    return st, rows


def cmd_match(args, today) -> int:
    header, data, _ = read_csv(args.csv)
    col = question_column(header, data, args.column)
    topics = json.loads(TOPICS.read_text(encoding="utf-8"))["topics"]
    st, rows = load_everything(args, today)
    items, out = {}, []
    for n, r in enumerate(data, 1):
        q = r[col] if col < len(r) else ""
        ts = match_topics(q, topics)
        ids = list(dict.fromkeys(i for t in ts for i in t["items"]))
        for i in ids:
            items[i] = {"title": rows[i]["title"], "state": rows[i]["state"], "severity": rows[i]["severity"]}
        out.append({"row": n, "question": q, "topics": [t["id"] for t in ts], "candidate_items": ids})
    print(json.dumps({"question_column": header[col], "columns": header, "stage": st["profile"].get("stage"),
                      "items": items, "rows": out}, indent=2))
    return 0


def cmd_render(args, today) -> int:
    header, data, dialect = read_csv(args.csv)
    col = question_column(header, data, args.column)
    answers = {}
    for a in json.loads(args.answers.read_text(encoding="utf-8")):
        if isinstance(a, dict) and isinstance(a.get("row"), int):
            answers[a["row"]] = a
    st, rows = load_everything(args, today)
    root = args.root.resolve()
    stage = st["profile"].get("stage", "launch")

    state_file = rr.load_json(args.dir / "state.json") or {}
    gen = rr._date(state_file.get("generated"))
    stale = (today - gen).days if gen else None

    out_rows, notes = [], []
    counts = {"yes": 0, "partial": 0, "no": 0, "unknown": 0, "na": 0}
    for n, r in enumerate(data, 1):
        a = answers.get(n)
        flags, mapped = [], []
        if a is None:
            requested, wanted, text = "unknown", [], ""
            flags.append("no answer was drafted for this row")
        else:
            requested = str(a.get("stance", "unknown")).lower()
            if requested not in (*RANK, "na"):
                flags.append(f"invalid stance {requested!r} treated as unknown")
                requested = "unknown"
            wanted = [i for i in dict.fromkeys(a.get("items") or []) if isinstance(i, str)]
            text = str(a.get("answer", ""))
        for i in wanted:
            if i in rows:
                mapped.append(rows[i])
            else:
                flags.append(f"unknown checklist item {i!r} ignored")
        if not mapped:
            allowed = "unknown"
            if a is not None:
                flags.append("no checklist item backs this answer")
        else:
            allowed = allowed_stance([category(m) for m in mapped])
        final = cap_stance(requested, allowed)
        overruled = final != requested
        if overruled:
            flags.append(f"stance lowered from {requested} to {final} by the audit results")
        if overruled or not mapped or not text.strip():
            if overruled and text.strip():
                notes.append(f"row {n}: the drafted {requested.upper()} answer was replaced with deterministic text ({final.upper()})")
            text = safe_answer(final, mapped)
        if stale is not None and stale > STALE_DAYS and final != "unknown":
            flags.append(f"audit is {stale} days old: re-run before sending")
        counts[final] = counts.get(final, 0) + 1
        basis = "; ".join(f"{m['id']} {m['state']}" for m in mapped)
        evidence = " | ".join(e for e in (evidence_cell(m, root) for m in mapped) if e)
        needs = " | ".join(x for x in (need_cell(m, stage) for m in mapped) if x)
        if final == "unknown" and not needs:
            needs = "Nothing in the audit covers this. Answer it yourself."
        full = list(r) + [""] * (len(header) - len(r))
        out_rows.append(full + ["DRAFT: " + final.upper(), text[:700], basis, evidence, needs, "; ".join(flags)])

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([neutralise(h) for h in header + NEW_COLUMNS])
        for row in out_rows:
            w.writerow([neutralise(c) for c in row])

    needs_input = sum(1 for r in out_rows if r[len(header) + 4])
    md = [f"# Questionnaire draft: {st['profile'].get('project', 'project')}", "",
          f"Generated {today.isoformat()} from the audit at stage **{stage}**. **Every answer is a draft for a person to review "
          f"before anything is sent to the buyer.**", "",
          "| Yes | Partial | No | Unknown | N/A |", "|---:|---:|---:|---:|---:|",
          f"| {counts['yes']} | {counts['partial']} | {counts['no']} | {counts['unknown']} | {counts['na']} |", "",
          f"{needs_input} of {len(out_rows)} rows need something from you (see the *Needs from founder* column).", ""]
    if stale is not None and stale > STALE_DAYS:
        md += [f"**The audit is {stale} days old.** Re-run `/ai-consultant:consult` first.", ""]
    if notes:
        md += ["## Where the audit overruled the draft", ""] + [f"- {x}" for x in notes] + [""]
    md += ["## How to read this", "",
           "- *Draft stance* is capped by the audit: it cannot be stronger than the weakest mapped checklist item.",
           "- *Evidence* lists real files and human attestations only. An empty cell means nothing verifiable backs the answer.",
           "- Answers marked UNKNOWN or NO are the honest ones. Do not rewrite them to YES until the underlying item is fixed and re-audited.", ""]
    args.out_md.write_text("\n".join(md), encoding="utf-8")
    print(f"wrote {args.out_csv} and {args.out_md}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".consultant", type=Path)
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--today", help="override date (YYYY-MM-DD), for tests")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("match")
    m.add_argument("--csv", required=True, type=Path)
    m.add_argument("--column")
    r = sub.add_parser("render")
    r.add_argument("--csv", required=True, type=Path)
    r.add_argument("--answers", required=True, type=Path)
    r.add_argument("--column")
    r.add_argument("--out-csv", required=True, type=Path)
    r.add_argument("--out-md", required=True, type=Path)
    args = ap.parse_args()
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    return {"match": cmd_match, "render": cmd_render}[args.cmd](args, today)


if __name__ == "__main__":
    sys.exit(main())
