#!/usr/bin/env python3
"""Render .consultant/REPORT.md from the profile and per-domain findings.

Standard library only. The verdict is computed here, by fixed rules, so it
does not depend on the mood of whichever model wrote the findings.

    python3 render_report.py [--dir .consultant] [--checklist PATH] [--ci]

Inputs (inside --dir):
    profile.json            {"project", "stage", "tags", "stack", "notes"}
    findings/<domain>.json  {"domain", "items": [{"id","status","evidence",
                             "summary","fix","question"}]}
    waivers.json            optional {"ITEM-ID": {"reason","accepted_by","expires"}}
    state.json              written by this script; used for "since last run"

Outputs: REPORT.md and state.json. With --ci, exit 1 if the verdict is NOT READY.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
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


def collect_findings(findings_dir: Path, known_ids: set[str]):
    """Return ({id: finding}, [warnings])."""
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
            if f["status"] == "na" and not f.get("summary"):
                warnings.append(f"{fid}: 'na' without a reason, downgraded to unknown")
                f["status"] = "unknown"
            if fid in found:
                warnings.append(f"{fid}: reported twice, last one wins")
            found[fid] = f
    return found, warnings


def active_waivers(waivers: dict, today: dt.date):
    active, expired = {}, {}
    for wid, w in (waivers or {}).items():
        try:
            exp = dt.date.fromisoformat(str(w.get("expires", "")))
        except ValueError:
            expired[wid] = {**w, "expires": f"{w.get('expires')!r} (invalid date)"}
            continue
        (active if exp >= today else expired)[wid] = w
    return active, expired


def build_rows(checklist: dict, profile: dict, findings: dict, waivers: dict):
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
    return "READY"


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


def render(profile, rows, warnings, expired_waivers, prev_state, today) -> tuple[str, dict]:
    verdict = verdict_for(rows)
    in_scope = [r for r in rows if r["state"] not in {"not-applicable", "later"}]
    counted = [r for r in in_scope if r["state"] != "na"]
    audited = [r for r in counted if r["state"] != "unaudited"]
    n = lambda st: sum(1 for r in counted if r["state"] == st)

    lines: list[str] = []
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
        "| Pass | Fail | Partial | Unknown | Waived | Not audited |",
        "|---:|---:|---:|---:|---:|---:|",
        f"| {n('pass')} | {n('fail')} | {n('partial')} | {n('unknown')} | {n('waived')} | {n('unaudited')} |",
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
        fixed = [r["id"] for r in counted if prev.get(r["id"]) in OPEN | {"unaudited"} and r["state"] in {"pass", "waived", "na"}]
        regressed = [r["id"] for r in counted if prev.get(r["id"]) == "pass" and r["state"] in OPEN]
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
            "(a screenshot, a document, a console setting) and re-run the consultant.",
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

    waived = [r for r in rows if r["state"] == "waived"]
    if waived or expired_waivers:
        lines += ["## Accepted risks", ""]
        for r in waived:
            lines.append(f"- {r['id']} · {r['title']}")
        for wid, w in expired_waivers.items():
            lines.append(f"- **EXPIRED** {wid}: expired {w.get('expires')}. It counts as open again.")
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
        "verdict": verdict,
        "statuses": {r["id"]: r["state"] for r in rows},
    }
    return "\n".join(lines).rstrip() + "\n", state


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default=".consultant", type=Path)
    ap.add_argument("--checklist", default=DEFAULT_CHECKLIST, type=Path)
    ap.add_argument("--today", help="override date (YYYY-MM-DD), for tests")
    ap.add_argument("--ci", action="store_true", help="exit 1 when the verdict is NOT READY")
    args = ap.parse_args()

    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    checklist = load_json(args.checklist)
    if checklist is None:
        sys.exit(f"checklist not found: {args.checklist}")
    profile = load_json(args.dir / "profile.json")
    if profile is None:
        sys.exit(f"{args.dir}/profile.json not found. Run the consult skill first.")
    if profile.get("stage", "launch") not in STAGE_TIER:
        sys.exit(f"profile.stage must be one of {sorted(STAGE_TIER)}")
    bad_tags = set(profile.get("tags", [])) - set(checklist["tags"])
    if bad_tags:
        sys.exit(f"profile has unknown tags: {sorted(bad_tags)}")

    known = {i["id"] for d in checklist["domains"] for i in d["items"]}
    findings, warnings = collect_findings(args.dir / "findings", known)
    waivers, expired = active_waivers(load_json(args.dir / "waivers.json", {}), today)
    rows = build_rows(checklist, profile, findings, waivers)
    prev = load_json(args.dir / "state.json")

    text, state = render(profile, rows, warnings, expired, prev, today)
    (args.dir / "REPORT.md").write_text(text, encoding="utf-8")
    (args.dir / "state.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(f"{state['verdict']}: wrote {args.dir}/REPORT.md")
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 1 if args.ci and state["verdict"] == "NOT READY" else 0


if __name__ == "__main__":
    sys.exit(main())
