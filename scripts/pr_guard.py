#!/usr/bin/env python3
"""Deterministic pull-request tripwires. No model, no secrets, safe on forked PRs.

This is NOT an audit. It catches the specific regressions a pull request can introduce
against the last audit recorded on the BASE branch:

  high    new dependency that does not exist on the registry, or imitates a popular one
  high    a file likely to hold secrets was added or changed (.env, keys, service accounts)
  high    a file cited as evidence for a passing control was deleted
  medium  lines cited as evidence for a passing control were changed or the file moved
  medium  the audit record (.consultant/ waivers, profile, findings) was edited in the PR
  medium  waivers that the report renderer would reject
  low     waivers expiring soon, audit older than N commits, no baseline audit at all

Trust model: the baseline (findings, waivers, state) is read from the BASE ref with `git show`,
never from the PR's working tree, so a PR cannot approve itself by editing .consultant/. The
PR's files are only ever read as data. Nothing from the PR is executed. File contents of
suspected secret files are never read or printed.

    python3 pr_guard.py --base origin/main [--head HEAD] [--root .] [--offline]
                        [--fail-on high|medium|low|none] [--out-md FILE] [--out-json FILE]

Standard library only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render_report  # noqa: E402
import verify_packages  # noqa: E402

MARKER = "<!-- ai-consultant-pr-guard -->"
RANK = {"low": 0, "medium": 1, "high": 2}
STALE_COMMITS = 50
WAIVER_WARN_DAYS = 14
CHECKLIST = Path(__file__).resolve().parent.parent / "checklist" / "checklist.json"

SECRET_FILES_HIGH = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_rsa.*", "id_ed25519",
                     "serviceAccount*.json", "*service-account*.json", "*serviceaccount*.json", "credentials.json",
                     "*.tfstate", "*.tfstate.backup"]
SECRET_FILES_MEDIUM = [".npmrc", ".pypirc", "*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.sql.gz"]
SECRET_FILES_OK = [".env.example", ".env.sample", ".env.template", ".env.defaults", "*.pub", "*.example.pem"]
AUDIT_FILES = {"waivers.json", "profile.json", "state.json"}


# ---------------------------------------------------------------- git helpers

class GitError(RuntimeError):
    pass


def git(root: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-c", "core.quotepath=off", "-C", str(root), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def show(root: Path, ref: str, path: str) -> str | None:
    proc = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{path}"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout if proc.returncode == 0 else None


def parse_name_status(raw: str) -> list[dict]:
    """Parse `git diff -z --name-status -M`: [status, path] or [Rnn, old, new]."""
    parts = raw.split("\0")
    out, i = [], 0
    while i < len(parts) and parts[i]:
        status = parts[i]
        if status[0] in "RC":
            out.append({"status": status[0], "old": parts[i + 1], "path": parts[i + 2]})
            i += 3
        else:
            out.append({"status": status[0], "path": parts[i + 1], "old": None})
            i += 2
    return out


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


def parse_old_ranges(diff_text: str) -> list[tuple[int, int, bool]]:
    """Old-side hunks as (start, end, is_pure_insertion). A pure insertion after line N is (N, N, True)."""
    ranges = []
    for m in HUNK.finditer(diff_text):
        start = int(m.group(1))
        count = 1 if m.group(2) is None else int(m.group(2))
        ranges.append((start, start, True) if count == 0 else (start, start + count - 1, False))
    return ranges


def parse_ref(ref: str):
    m = render_report.EVIDENCE_REF.match(str(ref).strip())
    if not m:
        return None
    start = int(m.group("line")) if m.group("line") else None
    end = int(m.group("end")) if m.group("end") else start
    return m.group("path"), start, end


def overlaps(cited: tuple[int, int], hunks) -> bool:
    s, e = cited
    for a, b, insertion in hunks:
        if insertion:
            if s <= a < e:
                return True
        elif a <= e and b >= s:
            return True
    return False


# ---------------------------------------------------------------- baseline

def load_baseline(root: Path, base: str) -> dict:
    """Read findings, waivers and state from the BASE ref only."""
    listing = git(root, "ls-tree", "-r", "--name-only", base, "--", ".consultant", check=False).splitlines()
    findings = {}
    for path in listing:
        if re.fullmatch(r"\.consultant/findings/[^/]+\.json", path):
            try:
                data = json.loads(show(root, base, path) or "{}")
            except json.JSONDecodeError:
                continue
            for item in data.get("items", []):
                if isinstance(item, dict) and "id" in item:
                    findings[item["id"]] = item

    def load(name):
        text = show(root, base, f".consultant/{name}")
        try:
            return json.loads(text) if text else None
        except json.JSONDecodeError:
            return None

    return {"findings": findings, "waivers": load("waivers.json") or {}, "state": load("state.json"),
            "has_audit": bool(listing)}


# ---------------------------------------------------------------- checks

def f(severity, kind, title, detail="", items=None, files=None):
    return {"severity": severity, "kind": kind, "title": title, "detail": detail,
            "items": items or [], "files": files or []}


def check_evidence_drift(root: Path, merge_base: str, head: str, baseline: dict, changes: list[dict]):
    by_path = {c["path"]: c for c in changes}
    by_old = {c["old"]: c for c in changes if c["old"]}
    deleted, moved, edited = {}, {}, {}
    hunk_cache: dict[str, list] = {}

    def hunks_for(path):
        if path not in hunk_cache:
            hunk_cache[path] = parse_old_ranges(git(root, "diff", "-U0", "--no-color", f"{merge_base}", head, "--", path, check=False))
        return hunk_cache[path]

    for iid, item in baseline["findings"].items():
        if item.get("status") != "pass":
            continue
        for ref in item.get("evidence") or []:
            parsed = parse_ref(ref)
            if not parsed or parsed[0].startswith(".consultant/"):
                continue
            path, start, end = parsed
            change = by_path.get(path) or by_old.get(path)
            if not change:
                continue
            if change["status"] == "D":
                deleted.setdefault(iid, []).append(ref)
            elif change["status"] in "RC" and change["old"] == path:
                moved.setdefault(iid, []).append(f"{ref} -> {change['path']}")
            elif change["status"] == "M":
                if start is None or overlaps((start, end), hunks_for(path)):
                    edited.setdefault(iid, []).append(ref)
    out = []
    if deleted:
        out.append(f("high", "evidence-deleted", "Code cited as evidence for passing controls was deleted",
                     "These controls passed in the last audit because of code this PR removes. They must be re-verified before merge.",
                     items=sorted(deleted), files=sorted({r for v in deleted.values() for r in v})))
    changed = {**moved}
    for iid, refs in edited.items():
        changed.setdefault(iid, []).extend(refs)
    if changed:
        out.append(f("medium", "evidence-changed", "Code cited as evidence for passing controls was changed",
                     "Re-run the consultant on these controls: `/ai-consultant:consult-audit <ids>`.",
                     items=sorted(changed), files=sorted({r for v in changed.values() for r in v})))
    return out


def matches_any(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def check_secret_files(changes: list[dict]):
    high, medium = [], []
    for c in changes:
        if c["status"] == "D":
            continue
        name = c["path"].rsplit("/", 1)[-1]
        if matches_any(name, SECRET_FILES_OK):
            continue
        if matches_any(name, SECRET_FILES_HIGH):
            high.append(c["path"])
        elif matches_any(name, SECRET_FILES_MEDIUM):
            medium.append(c["path"])
    out = []
    if high:
        out.append(f("high", "secret-file", "Files that usually contain secrets were added or changed",
                     "Contents were not read or printed. If any real credential was committed, rotate it: removing the file does not remove it from git history.",
                     files=sorted(high)))
    if medium:
        out.append(f("medium", "sensitive-file", "Files that may contain credentials or data dumps were added or changed",
                     "Check that these belong in the repository.", files=sorted(medium)))
    return out


def check_audit_record(root: Path, head: str, changes: list[dict], baseline: dict, today: dt.date):
    out = []
    touched = [c["path"] for c in changes if c["path"].startswith(".consultant/")
               and not c["path"].startswith(".consultant/facts/") and c["path"] != ".consultant/REPORT.md"]
    if touched:
        out.append(f("medium", "audit-record-changed", "The audit record was edited in this PR",
                     "Waivers, the profile and findings change what the report says, so a reviewer should read these edits as carefully as code. "
                     "This guard compares against the base branch, so edits here do not affect its own result.",
                     files=sorted(touched)))
    # waivers as they will be after merge
    raw = show(root, head, ".consultant/waivers.json")
    if raw:
        try:
            waivers = json.loads(raw)
            checklist = json.loads(CHECKLIST.read_text(encoding="utf-8"))
            sev = {i["id"]: i["severity"] for d in checklist["domains"] for i in d["items"]}
            _, _, rejected = render_report.active_waivers(waivers, today, sev)
            if rejected:
                out.append(f("medium", "waivers-rejected", "Some waivers in this PR would be rejected by the report renderer",
                             "; ".join(f"{k}: {v}" for k, v in sorted(rejected.items()))[:600], items=sorted(rejected)))
        except (json.JSONDecodeError, OSError):
            out.append(f("medium", "waivers-invalid", "waivers.json in this PR is not valid JSON"))
    # waivers about to lapse on the base branch
    soon = []
    for wid, w in (baseline["waivers"] or {}).items():
        exp = render_report._date(w.get("expires")) if isinstance(w, dict) else None
        if exp and today <= exp <= today + dt.timedelta(days=WAIVER_WARN_DAYS):
            soon.append(f"{wid} ({exp.isoformat()})")
    if soon:
        out.append(f("low", "waivers-expiring", f"Accepted risks expire within {WAIVER_WARN_DAYS} days",
                     ", ".join(sorted(soon))))
    return out


def check_staleness(root: Path, head: str, baseline: dict):
    if not baseline["has_audit"]:
        return [f("low", "no-baseline", "No audit record on the base branch",
                  "Run `/ai-consultant:consult` and commit `.consultant/` so pull requests can be checked against it.")]
    commit = (baseline["state"] or {}).get("commit")
    if commit:
        raw = git(root, "rev-list", "--count", f"{commit}..{head}", check=False).strip()
        if raw.isdigit() and int(raw) > STALE_COMMITS:
            return [f("low", "stale-audit", f"The last audit is {raw} commits behind",
                      "Re-run `/ai-consultant:consult` to refresh the baseline.")]
    return []


def manifests_in(root: Path, ref: str) -> list[str]:
    names = git(root, "ls-tree", "-r", "--name-only", ref, check=False).splitlines()
    return [n for n in names
            if not any(part in verify_packages.SKIP_DIRS for part in n.split("/")[:-1])
            and (n.endswith("package.json") or n.endswith("pyproject.toml")
                 or (n.rsplit("/", 1)[-1].startswith("requirements") and n.endswith(".txt")))
            and (n.rsplit("/", 1)[-1] in ("package.json", "pyproject.toml") or n.endswith(".txt"))][:200]


def base_package_set(root: Path, base: str) -> set:
    with tempfile.TemporaryDirectory() as tmp:
        for path in manifests_in(root, base):
            text = show(root, base, path)
            if text is not None:
                target = Path(tmp) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
        return {(p["ecosystem"], p["name"]) for p in verify_packages.collect(Path(tmp))}


def check_new_packages(root: Path, base: str, offline: bool, fetch=verify_packages.http_json, now=None):
    head_set = {(p["ecosystem"], p["name"]) for p in verify_packages.collect(root)}
    new = head_set - base_package_set(root, base)
    if not new:
        return [], 0
    res = verify_packages.run(root, offline=offline, fetch=fetch, now=now, only=new)
    out = []
    for p in res["flagged"]:
        codes = [fl["code"] for fl in p["flags"]]
        if p["risk"] in ("high", "medium"):
            out.append(f(p["risk"], "new-package", f"New dependency `{p['name']}` ({p['ecosystem']}) needs a look: {', '.join(codes)}",
                         " ".join(fl["explanation"] for fl in p["flags"])[:500], files=p["declared_in"]))
    if res["unreachable"]:
        out.append(f("low", "registry-unreachable", "Some new dependencies could not be checked",
                     f"Registry unreachable for: {', '.join(res['unreachable'][:10])}"))
    return out, len(new)


# ---------------------------------------------------------------- orchestration

def run(root: Path, base: str, head: str = "HEAD", offline: bool = False, fetch=verify_packages.http_json,
        today: dt.date | None = None, now=None) -> dict:
    today = today or dt.date.today()
    merge_base = git(root, "merge-base", base, head).strip()
    changes = parse_name_status(git(root, "diff", "-z", "--name-status", "-M", merge_base, head))
    baseline = load_baseline(root, base)

    findings: list[dict] = []
    findings += check_evidence_drift(root, merge_base, head, baseline, changes)
    findings += check_secret_files(changes)
    findings += check_audit_record(root, head, changes, baseline, today)
    pkg_findings, new_count = check_new_packages(root, base, offline, fetch, now)
    findings += pkg_findings
    findings += check_staleness(root, head, baseline)
    findings.sort(key=lambda x: -RANK[x["severity"]])
    passing = sum(1 for i in baseline["findings"].values() if i.get("status") == "pass")
    return {"base": base, "head": head, "merge_base": merge_base, "changed_files": len(changes),
            "new_packages_checked": new_count, "passing_controls_tracked": passing, "findings": findings}


def safe(text, limit=160) -> str:
    """Neutralise PR-controlled text before it goes into markdown (names are attacker-chosen)."""
    s = re.sub(r"[`\r\n<>\[\]|]", " ", str(text)).strip()
    return s[:limit] + ("…" if len(s) > limit else "")


def to_markdown(result: dict) -> str:
    fs = result["findings"]
    blocking = [x for x in fs if x["severity"] == "high"]
    head = (f"{len(blocking)} blocking, {len(fs) - len(blocking)} to review" if fs else "no issues found")
    lines = [MARKER, f"### AI-Consultant PR guard: {head}", ""]
    if not fs:
        lines += [f"Checked {result['changed_files']} changed files, {result['new_packages_checked']} new dependencies, "
                  f"and {result['passing_controls_tracked']} passing controls from the last audit.", ""]
    icon = {"high": "🔴", "medium": "🟠", "low": "⚪"}
    for x in fs:
        lines.append(f"{icon[x['severity']]} **{x['severity'].upper()}** · {safe(x['title'], 200)}")
        if x["detail"]:
            lines.append(f"  {safe(x['detail'], 600)}")
        if x["items"]:
            lines.append("  Controls: " + ", ".join(f"`{safe(i, 20)}`" for i in x["items"][:20]))
        if x["files"]:
            shown = x["files"][:10]
            lines.append("  Files: " + ", ".join(f"`{safe(p)}`" for p in shown) + (f" and {len(x['files']) - 10} more" if len(x["files"]) > 10 else ""))
        lines.append("")
    lines += ["<sub>A tripwire against the last recorded audit on the base branch, not a security review. "
              "It reads no code from this PR and executes nothing. "
              "[AI-Consultant](https://github.com/adibM04/AI-Consultant)</sub>"]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, help="base ref, e.g. origin/main")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--offline", action="store_true", help="skip registry lookups")
    ap.add_argument("--fail-on", choices=("high", "medium", "low", "none"), default="high")
    ap.add_argument("--out-md", type=Path)
    ap.add_argument("--out-json", type=Path)
    args = ap.parse_args()

    try:
        result = run(args.root.resolve(), args.base, args.head, offline=args.offline)
    except GitError as exc:
        print(f"error: {exc}\nHint: the workflow needs `fetch-depth: 0` so the base branch is available.", file=sys.stderr)
        return 2
    md = to_markdown(result)
    if args.out_md:
        args.out_md.write_text(md, encoding="utf-8")
    if args.out_json:
        args.out_json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(md)
    if args.fail_on != "none" and any(RANK[x["severity"]] >= RANK[args.fail_on] for x in result["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
