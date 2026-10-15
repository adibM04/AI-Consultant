#!/usr/bin/env python3
"""Render .consultant/REPORT.md from the profile and per-domain findings.

Standard library only. The verdict is computed here, by fixed rules, so it
does not depend on the mood of whichever model wrote the findings.

    python3 render_report.py [--dir .consultant] [--root .] [--checklist PATH] [--ci]

A `pass` must cite evidence that resolves to a real file (and line) under --root.
Anything else is downgraded to `unknown`, so a fabricated or injected "pass" cannot
survive the renderer.

Inputs (inside --dir):
    profile.json            {"project", "stage", "tags", "stack", "notes"}
    findings/<domain>.json  {"domain", "items": [{"id","status","evidence",
                             "summary","fix","question"}]}
    waivers.json            optional {"ITEM-ID": {"reason","accepted_by","created","expires"}}.
                            Validated here: created <= today, expires within 180 days of
                            created (90 for critical items), all fields present.
    attestations.json       optional {"ITEM-ID": {"attested_by","date","expires","note","evidence":[path]}}.
                            A founder's signed statement that a process or console item is satisfied
                            (a restore test, a key rotation). Only for items a repository cannot show
                            (checklist evidence "process" or "config"), only to settle an item that is
                            otherwise unknown, never to override a failing finding. Needs an evidence
                            file that exists, and expires within a year. Listed prominently; the tool
                            does not verify it.
    state.json              written by this script; used for "since last run"

Outputs: REPORT.md and state.json. With --ci, exit 1 if the verdict is NOT READY.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_CHECKLIST = Path(__file__).resolve().parent.parent / "checklist" / "checklist.json"

STAGE_TIER = {"launch": 1, "growth": 2, "enterprise": 3}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
VALID_STATUS = {"pass", "fail", "partial", "unknown", "na"}
OPEN = {"fail", "partial", "unknown"}  # statuses that still need work or confirmation

VERDICTS = {
    "NOT READY": "At least one critical gap is confirmed. Do not put paying customers on this until the blockers below are fixed.",
    "NOT VERIFIED": "No critical gap was found, but critical items could not be verified from the repository. Someone must confirm them.",
    "CONDITIONAL": "No critical gaps. Important issues remain; fix or consciously accept them before you scale.",
    "READY": "No known gaps in what was checked for this stage. This is a checklist result, not a guarantee of safety.",
}

ROLE_LABELS = {
    "senior-engineer": "Senior engineer",
    "backend-engineer": "Backend engineer",
    "frontend-engineer": "Frontend engineer",
    "devops": "DevOps engineer",
    "security": "Security engineer",
    "compliance": "Compliance / privacy lead",
    "legal": "Lawyer",
    "finance": "Finance / accountant",
    "qa": "QA engineer",
    "tech-lead": "Tech lead",
    "architect": "Architect",
}


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.exit(f"{path}: invalid JSON ({exc})")


def applies(item: dict, tags: set[str]) -> bool:
    when = item.get("when") or []
    return not when or bool(set(when) & tags)


EVIDENCE_REF = re.compile(r"^(?P<path>[^\s:][^:]*?)(?::(?P<line>\d+)(?:-(?P<end>\d+))?)?$")


def evidence_resolves(ref, root: Path) -> bool:
    """True if `ref` is `path`, `path:line` or `path:start-end` naming a real file inside root (not under .consultant)."""
    m = EVIDENCE_REF.match(str(ref).strip())
    if not m:
        return False
    try:
        base = root.resolve()
        target = (base / m.group("path")).resolve()
        rel = target.relative_to(base)
    except (ValueError, OSError):
        return False
    if rel.parts and rel.parts[0] == ".consultant":
        return False
    if not target.is_file():
        return False
    if m.group("line"):
        try:
            with target.open("rb") as fh:
                total = sum(1 for _ in fh)
        except OSError:
            return False
        start, end = int(m.group("line")), int(m.group("end") or m.group("line"))
        return 1 <= start <= end <= max(total, 1)
    return True


def collect_findings(findings_dir: Path, known_ids: set[str], root: Path | None = None):
    """Return ({id: finding}, [warnings]). With `root`, a pass must cite evidence that exists there."""
    found: dict[str, dict] = {}
    warnings: list[str] = []
    for path in sorted(findings_dir.glob("*.json")):
        data = load_json(path, {})
        for f in data.get("items", []):
            fid = f.get("id")
            if fid not in known_ids:
                warnings.append(f"{path.name}: unknown checklist id '{fid}' ignored")
                continue
            status = f.get("status")
            if status not in VALID_STATUS:
                warnings.append(f"{fid}: invalid status '{status}', treated as unknown")
                f["status"] = "unknown"
            if f["status"] == "pass" and not f.get("evidence"):
                warnings.append(f"{fid}: 'pass' without evidence, downgraded to unknown")
                f["status"] = "unknown"
                f["summary"] = (f.get("summary") or "") + " (pass claimed without evidence)"
            elif f["status"] == "pass" and root is not None and not any(evidence_resolves(e, root) for e in f["evidence"]):
                warnings.append(f"{fid}: 'pass' evidence does not point to a real file/line in the project, downgraded to unknown")
                f["status"] = "unknown"
                f["summary"] = (f.get("summary") or "") + " (pass evidence could not be verified)"
            if f["status"] == "na" and not f.get("summary"):
                warnings.append(f"{fid}: 'na' without a reason, downgraded to unknown")
                f["status"] = "unknown"
            if fid in found:
                warnings.append(f"{fid}: reported twice, last one wins")
            found[fid] = f
    return found, warnings


WAIVER_MAX_DAYS = 180
WAIVER_MAX_DAYS_CRITICAL = 90


def _date(value):
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        return None


def active_waivers(waivers: dict, today: dt.date, severities: dict | None = None):
    """Split waivers into (active, expired, rejected).

    A waiver is only honoured if it names a known item, carries a reason, an accepted_by and a
    created date that is not in the future, and expires within 180 days of creation (90 for
    critical items). Anything else is rejected with the reason, so a pre-planted waivers.json
    cannot silence findings.
    """
    active, expired, rejected = {}, {}, {}
    for wid, w in (waivers or {}).items():
        if not isinstance(w, dict):
            rejected[wid] = "not an object"
            continue
        if severities is not None and wid not in severities:
            rejected[wid] = "unknown checklist item"
            continue
        if not str(w.get("reason", "")).strip() or not str(w.get("accepted_by", "")).strip():
            rejected[wid] = "missing reason or accepted_by"
            continue
        created, exp = _date(w.get("created")), _date(w.get("expires"))
        if created is None or exp is None:
            rejected[wid] = "missing or invalid created/expires date"
            continue
        if created > today:
            rejected[wid] = "created date is in the future"
            continue
        limit = WAIVER_MAX_DAYS_CRITICAL if (severities or {}).get(wid) == "critical" else WAIVER_MAX_DAYS
        if (exp - created).days > limit:
            rejected[wid] = f"expires more than {limit} days after it was created"
            continue
        (active if exp >= today else expired)[wid] = w
    return active, expired, rejected


ATTEST_MAX_DAYS = 365
ATTESTABLE = {"process", "config"}


def active_attestations(attestations: dict, today: dt.date, items: dict, root: Path | None = None):
    """Split attestations into (active, expired, rejected). `items` maps checklist id -> item.

    Rejected unless: known item; the item is not code-checkable (a statement cannot replace
    reading the code); attested_by and note present; date not in the future; expires after date
    and within a year; and, when `root` is given, at least one evidence file really exists.
    """
    active, expired, rejected = {}, {}, {}
    for iid, a in (attestations or {}).items():
        item = items.get(iid)
        if not isinstance(a, dict):
            rejected[iid] = "not an object"
        elif item is None:
            rejected[iid] = "unknown checklist item"
        elif item.get("evidence") not in ATTESTABLE:
            rejected[iid] = "this item can be checked in code, so it must pass on the code, not on a statement"
        elif not str(a.get("attested_by", "")).strip() or not str(a.get("note", "")).strip():
            rejected[iid] = "missing attested_by or note"
        else:
            date, exp = _date(a.get("date")), _date(a.get("expires"))
            refs = a.get("evidence") if isinstance(a.get("evidence"), list) else []
            if date is None or exp is None:
                rejected[iid] = "missing or invalid date/expires"
            elif date > today:
                rejected[iid] = "date is in the future"
            elif exp <= date or (exp - date).days > ATTEST_MAX_DAYS:
                rejected[iid] = f"expires must be after the date and within {ATTEST_MAX_DAYS} days of it"
            elif root is not None and not any(evidence_resolves(r, root) for r in refs):
                rejected[iid] = "no evidence file found at the stated path"
            else:
                (active if exp >= today else expired)[iid] = a
    return active, expired, rejected


def build_rows(checklist: dict, profile: dict, findings: dict, waivers: dict, attestations: dict | None = None):
    tags = set(profile.get("tags", []))
    max_tier = STAGE_TIER.get(profile.get("stage", "launch"), 1)
    rows = []
    for dom in checklist["domains"]:
        for item in dom["items"]:
            row = {**item, "domain": dom["domain"], "domain_title": dom["title"]}
            if not applies(item, tags):
                row["state"] = "not-applicable"
            elif item["tier"] > max_tier:
                row["state"] = "later"
            else:
                f = findings.get(item["id"])
                if f is None:
                    row["state"] = "unaudited"
                    row["status"] = "unknown"
                else:
                    row["status"] = f["status"]
                    row["finding"] = f
                    row["state"] = "na" if f["status"] == "na" else f["status"]
                att = (attestations or {}).get(item["id"])
                if att and row["state"] in {"unknown", "unaudited"}:
                    row["state"], row["attestation"] = "attested", att
                elif att and row["state"] in {"fail", "partial"}:
                    row["attestation_ignored"] = True  # a failing code finding is never overridden by a statement
                if item["id"] in waivers and row["state"] in OPEN | {"unaudited"}:
                    row["state"] = "waived"
            rows.append(row)
    return rows


def is_open(row) -> bool:
    return row["state"] in OPEN or row["state"] == "unaudited"


def verdict_for(rows) -> str:
    crit = [r for r in rows if r["severity"] == "critical"]
    if any(r["state"] in {"fail", "partial"} for r in crit):
        return "NOT READY"
    if any(r["state"] in {"unknown", "unaudited"} for r in crit):
        return "NOT VERIFIED"
    if any(is_open(r) for r in rows if r["severity"] == "high"):
        return "CONDITIONAL"
    if any(r["state"] == "waived" for r in crit):
        return "CONDITIONAL"  # a knowingly accepted critical risk is never "ready"
    return "READY"


def current_commit() -> str | None:
    """HEAD of the project the report is rendered in, if it is a git checkout (used for staleness checks)."""
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else None


def fmt_evidence(ev) -> str:
    if not ev:
        return ""
    return ", ".join(f"`{e}`" for e in ev)


def render_item(row) -> list[str]:
    f = row.get("finding", {})
    status = row["state"]
    tag = {"fail": "FAIL", "partial": "PARTIAL", "unknown": "UNKNOWN", "unaudited": "NOT AUDITED"}.get(status, status.upper())
    out = [f"#### {row['id']} · {row['title']}", ""]
    out.append(f"`{tag}` · {row['severity']} · owner: {ROLE_LABELS.get(row['role'], row['role'])} · tier {row['tier']}")
    out.append("")
    if f.get("summary"):
        out += [f["summary"], ""]
    if f.get("evidence"):
        out += [f"Evidence: {fmt_evidence(f['evidence'])}", ""]
    if f.get("fix") and status in {"fail", "partial"}:
        out += [f"**Fix:** {f['fix']}", ""]
    if status in {"unknown", "unaudited"}:
        q = f.get("question") or f"Show evidence for: {row['check']}"
        out += [f"**To confirm:** {q}", ""]
    return out


def group(rows, pred):
    by_sev = {s: [r for r in rows if pred(r) and r["severity"] == s] for s in SEVERITY_ORDER}
    return by_sev


def render(profile, rows, warnings, expired_waivers, prev_state, today, waivers=None, rejected_waivers=None,
           attest=None) -> tuple[str, dict]:
    attest_expired, attest_rejected = (attest or ({}, {}))
    verdict = verdict_for(rows)
    in_scope = [r for r in rows if r["state"] not in {"not-applicable", "later"}]
    counted = [r for r in in_scope if r["state"] != "na"]
    audited = [r for r in counted if r["state"] != "unaudited"]
    n = lambda st: sum(1 for r in counted if r["state"] == st)

    lines: list[str] = []
    attested_rows = [r for r in rows if r["state"] == "attested"]
    lines += [
        f"# Production readiness report: {profile.get('project', 'this project')}",
        "",
        f"Generated {today.isoformat()} · stage: **{profile.get('stage', 'launch')}** · "
        f"tags: {', '.join(profile.get('tags', [])) or 'none'}",
        "",
        f"## Verdict: {verdict}",
        "",
        VERDICTS[verdict],
        "",
    ]
    if attested_rows:
        lines += [f"This verdict relies on {len(attested_rows)} item(s) settled by a person's attestation rather than by the code "
                  f"({sum(1 for r in attested_rows if r['severity'] == 'critical')} critical). The tool did not verify them; see Human attestations below.", ""]
    lines += [
        "| Pass | Fail | Partial | Unknown | Attested | Waived | Not audited |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {n('pass')} | {n('fail')} | {n('partial')} | {n('unknown')} | {n('attested')} | {n('waived')} | {n('unaudited')} |",
        "",
        f"Coverage: {len(audited)} of {len(counted)} in-scope items audited. "
        f"{sum(1 for r in rows if r['state'] == 'later')} items are deferred to later stages and "
        f"{sum(1 for r in rows if r['state'] == 'not-applicable')} do not apply to this product.",
        "",
        "> This report comes from reading the repository and answers the founder gave. "
        "It cannot see your cloud console, DNS, contracts or processes, so those items show as "
        "UNKNOWN until someone confirms them. It does not replace a penetration test, an auditor, "
        "or an engineer who understands your system.",
        "",
    ]

    if prev_state:
        prev = prev_state.get("statuses", {})
        fixed = [r["id"] for r in counted if prev.get(r["id"]) in OPEN | {"unaudited"} and r["state"] in {"pass", "waived", "na", "attested"}]
        regressed = [r["id"] for r in counted if prev.get(r["id"]) in {"pass", "attested"} and r["state"] in OPEN | {"unaudited"}]
        lines += [
            "## Since the last run",
            "",
            f"Fixed or closed: {len(fixed)} ({', '.join(fixed) or 'none'}) · "
            f"Regressed: {len(regressed)} ({', '.join(regressed) or 'none'})",
            "",
        ]

    fails = group(counted, lambda r: r["state"] in {"fail", "partial"})
    for sev, heading in (("critical", "Blockers (critical)"), ("high", "Important (high)")):
        if fails[sev]:
            lines += [f"## {heading}", ""]
            for r in fails[sev]:
                lines += render_item(r)
    rest = fails["medium"] + fails["low"]
    if rest:
        lines += ["## Worth fixing (medium and low)", ""]
        for r in rest:
            lines += render_item(r)

    unknown = [r for r in counted if r["state"] in {"unknown", "unaudited"}]
    if unknown:
        lines += [
            "## Needs a human to confirm",
            "",
            "These could not be established from the repository. Answer each with evidence "
            "(a screenshot, a document, a console setting) and record it with `/ai-consultant:consult-evidence`.",
            "",
        ]
        for sev in SEVERITY_ORDER:
            for r in (u for u in unknown if u["severity"] == sev):
                lines += render_item(r)

    open_rows = [r for r in counted if r["state"] in OPEN | {"unaudited"}]
    by_role: dict[str, list] = {}
    for r in open_rows:
        by_role.setdefault(r["role"], []).append(r)
    if by_role:
        lines += [
            "## People this product still needs",
            "",
            "Open items grouped by the kind of person who normally owns them.",
            "",
            "| Role | Open items | Critical | Most urgent |",
            "|---|---:|---:|---|",
        ]
        for role, rs in sorted(by_role.items(), key=lambda kv: (-sum(1 for r in kv[1] if r["severity"] == "critical"), -len(kv[1]))):
            rs_sorted = sorted(rs, key=lambda r: SEVERITY_ORDER.index(r["severity"]))
            lines.append(
                f"| {ROLE_LABELS.get(role, role)} | {len(rs)} | "
                f"{sum(1 for r in rs if r['severity'] == 'critical')} | {rs_sorted[0]['id']} {rs_sorted[0]['title'][:70]} |"
            )
        lines.append("")

    later = [r for r in rows if r["state"] == "later"]
    if later:
        lines += [
            "## Coming up at later stages",
            "",
            "Not counted against the verdict yet. Plan for these before you move up a stage.",
            "",
        ]
        for r in sorted(later, key=lambda r: (r["tier"], SEVERITY_ORDER.index(r["severity"]))):
            lines.append(f"- tier {r['tier']} · {r['id']} · {r['title']}")
        lines.append("")

    if attested_rows or attest_expired or attest_rejected:
        lines += ["## Human attestations", "",
                  "Statements by a person that something the code cannot show is true. The tool did not verify these; "
                  "they stop counting when they expire.", ""]
        for r in attested_rows:
            a = r["attestation"]
            lines.append(f"- {r['id']} · {r['severity']} · {r['title']}. Attested by {a.get('attested_by')} on {a.get('date')}, "
                         f"valid until {a.get('expires')}: {str(a.get('note'))[:200]} (evidence: {fmt_evidence(a.get('evidence'))})")
        for iid, a in attest_expired.items():
            lines.append(f"- **EXPIRED** {iid}: attested {a.get('date')}, expired {a.get('expires')}. The item is unknown again.")
        for iid, why in attest_rejected.items():
            lines.append(f"- **REJECTED** {iid}: {why}. The attestation was ignored.")
        lines.append("")

    waived = [r for r in rows if r["state"] == "waived"]
    if waived or expired_waivers or rejected_waivers:
        lines += ["## Accepted risks", ""]
        for r in waived:
            w = (waivers or {}).get(r["id"], {})
            lines.append(f"- {r['id']} · {r['severity']} · {r['title']}. Accepted by {w.get('accepted_by')} "
                         f"until {w.get('expires')}: {str(w.get('reason'))[:200]}")
        for wid, w in expired_waivers.items():
            lines.append(f"- **EXPIRED** {wid}: expired {w.get('expires')}. It counts as open again.")
        for wid, why in (rejected_waivers or {}).items():
            lines.append(f"- **REJECTED** {wid}: {why}. The waiver was ignored and the item counts as open.")
        lines.append("")

    passed = [r for r in counted if r["state"] == "pass"]
    if passed:
        lines += ["<details><summary>Passed (" + str(len(passed)) + ")</summary>", ""]
        for r in passed:
            ev = fmt_evidence(r["finding"].get("evidence"))
            lines.append(f"- {r['id']} · {r['title']}" + (f" ({ev})" if ev else ""))
        lines += ["", "</details>", ""]

    if warnings:
        lines += ["## Report warnings", ""] + [f"- {w}" for w in warnings] + [""]

    state = {
        "generated": today.isoformat(),
        "commit": current_commit(),
        "verdict": verdict,
        "statuses": {r["id"]: r["state"] for r in rows},
    }
    return "\n".join(lines).rstrip() + "\n", state


def load_state(audit_dir: Path, root: Path, checklist_path: Path = DEFAULT_CHECKLIST, today: dt.date | None = None) -> dict:
    """Load everything and compute the per-item rows. Shared by the report and the questionnaire tool."""
    today = today or dt.date.today()
    checklist = load_json(checklist_path)
    if checklist is None:
        sys.exit(f"checklist not found: {checklist_path}")
    profile = load_json(audit_dir / "profile.json")
    if profile is None:
        sys.exit(f"{audit_dir}/profile.json not found. Run the consult skill first.")
    if profile.get("stage", "launch") not in STAGE_TIER:
        sys.exit(f"profile.stage must be one of {sorted(STAGE_TIER)}")
    bad_tags = set(profile.get("tags", [])) - set(checklist["tags"])
    if bad_tags:
        sys.exit(f"profile has unknown tags: {sorted(bad_tags)}")

    items = {i["id"]: i for d in checklist["domains"] for i in d["items"]}
    severities = {k: v["severity"] for k, v in items.items()}
    findings, warnings = collect_findings(audit_dir / "findings", set(items), root=root)
    waivers, w_expired, w_rejected = active_waivers(load_json(audit_dir / "waivers.json", {}), today, severities)
    attest, a_expired, a_rejected = active_attestations(load_json(audit_dir / "attestations.json", {}), today, items, root)
    rows = build_rows(checklist, profile, findings, waivers, attest)
    for r in rows:
        if r.get("attestation_ignored"):
            warnings.append(f"{r['id']}: an attestation exists but the code finding is {r['state']}; the attestation was ignored")
    return {"checklist": checklist, "profile": profile, "rows": rows, "warnings": warnings, "today": today,
            "findings": findings, "waivers": waivers, "waivers_expired": w_expired, "waivers_rejected": w_rejected,
            "attestations": attest, "attest_expired": a_expired, "attest_rejected": a_rejected}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".consultant", type=Path)
    ap.add_argument("--root", default=".", type=Path, help="project root that evidence paths are resolved against")
    ap.add_argument("--checklist", default=DEFAULT_CHECKLIST, type=Path)
    ap.add_argument("--today", help="override date (YYYY-MM-DD), for tests")
    ap.add_argument("--ci", action="store_true", help="exit 1 when the verdict is NOT READY")
    args = ap.parse_args()

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    st = load_state(args.dir, args.root, args.checklist, today)
    prev = load_json(args.dir / "state.json")

    text, state = render(st["profile"], st["rows"], st["warnings"], st["waivers_expired"], prev, today, st["waivers"],
                         st["waivers_rejected"], (st["attest_expired"], st["attest_rejected"]))
    (args.dir / "REPORT.md").write_text(text, encoding="utf-8")
    (args.dir / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(f"{state['verdict']}: wrote {args.dir}/REPORT.md")
    for w in st["warnings"]:
        print(f"warning: {w}", file=sys.stderr)
    for wid, why in st["waivers_rejected"].items():
        print(f"warning: waiver {wid} rejected: {why}", file=sys.stderr)
    for iid, why in st["attest_rejected"].items():
        print(f"warning: attestation {iid} rejected: {why}", file=sys.stderr)
    return 1 if args.ci and state["verdict"] == "NOT READY" else 0


if __name__ == "__main__":
    sys.exit(main())
