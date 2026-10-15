#!/usr/bin/env python3
"""Run whichever open-source scanners are installed and normalise their output.

Deterministic tools produce the facts; the auditors interpret them. Supported:

    gitleaks     secrets in the working tree AND git history
    osv-scanner  known-vulnerable dependencies (OSV database)
    trivy        vulnerabilities, secrets and misconfigurations in the filesystem
    semgrep      static analysis (opt-in with --semgrep: it downloads rule packs)

Missing tools are reported, never installed. Nothing here modifies the project.
Secret VALUES are never copied into the output: gitleaks runs with --redact and
every normaliser drops match/secret/code fields as a second line of defence.
gitleaks and osv-scanner are fully local after install; trivy downloads its
vulnerability database; semgrep downloads rules (metrics are disabled).

Standard library only.

    python3 run_scanners.py [--root .] [--out .consultant/facts/scanners.json] [--semgrep]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_FINDINGS_PER_TOOL = 200
TIMEOUT_SECONDS = 900

INSTALL_HINTS = {
    "gitleaks": "brew install gitleaks  (or https://github.com/gitleaks/gitleaks)",
    "osv-scanner": "brew install osv-scanner  (or https://github.com/google/osv-scanner)",
    "trivy": "brew install trivy  (or https://github.com/aquasecurity/trivy)",
    "semgrep": "pip install semgrep  (or brew install semgrep)",
}


def finding(tool, rule, severity, file, line, message, checklist):
    return {"tool": tool, "rule": rule, "severity": severity, "file": file, "line": line,
            "message": message[:300], "checklist": checklist}


# ---------------------------------------------------------------- normalisers

def parse_gitleaks(data) -> list[dict]:
    out = []
    for r in data or []:
        # Deliberately ignore Secret, Match, Line (the raw source line) and Fingerprint.
        loc = r.get("File", "")
        if r.get("Commit"):
            loc_note = f" (in git history, commit {str(r['Commit'])[:8]})"
        else:
            loc_note = ""
        out.append(finding("gitleaks", r.get("RuleID", "secret"), "high", loc, r.get("StartLine"),
                           (r.get("Description") or "Possible secret") + loc_note, ["SEC-01", "SEC-02"]))
    return out


def _osv_severity(group_scores) -> str:
    scores = []
    for s in group_scores:
        try:
            scores.append(float(s))
        except (TypeError, ValueError):
            pass
    if not scores:
        return "medium"
    top = max(scores)
    return "critical" if top >= 9 else "high" if top >= 7 else "medium" if top >= 4 else "low"


def parse_osv(data) -> list[dict]:
    out = []
    for res in (data or {}).get("results", []):
        src = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []):
            p = pkg.get("package") or {}
            scores = {}
            for g in pkg.get("groups", []):
                for gid in g.get("ids", []):
                    scores[gid] = g.get("max_severity")
            for v in pkg.get("vulnerabilities", []):
                vid = v.get("id", "OSV")
                sev = _osv_severity([scores.get(vid)] + [scores.get(a) for a in v.get("aliases", [])])
                out.append(finding("osv-scanner", vid, sev, src, None,
                                   f"{p.get('name')}@{p.get('version')} ({p.get('ecosystem')}): {v.get('summary') or 'known vulnerability'}",
                                   ["SEC-04", "MNT-05"]))
    return out


def parse_trivy(data) -> list[dict]:
    out = []
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
    for res in (data or {}).get("Results", []):
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            out.append(finding("trivy", v.get("VulnerabilityID", "vuln"), sev_map.get(v.get("Severity"), "low"), target, None,
                               f"{v.get('PkgName')}@{v.get('InstalledVersion')}: {v.get('Title') or 'vulnerability'}"
                               + (f" (fixed in {fixed})" if fixed else ""), ["SEC-04", "MNT-05"]))
        for s in res.get("Secrets") or []:  # drop Match / Code: they contain the secret
            out.append(finding("trivy", s.get("RuleID", "secret"), sev_map.get(s.get("Severity"), "high"), target,
                               s.get("StartLine"), s.get("Title") or "Possible secret", ["SEC-01", "SEC-02"]))
        for m in res.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            out.append(finding("trivy", m.get("ID", "misconfig"), sev_map.get(m.get("Severity"), "medium"), target,
                               cause.get("StartLine"), m.get("Title") or m.get("Message") or "Misconfiguration",
                               ["SEC-12", "INF-02"]))
    return out


_SEMGREP_MAP = (("sql", "SEC-06"), ("xss", "SEC-05"), ("csrf", "SEC-07"), ("ssrf", "SEC-08"), ("path-traversal", "SEC-08"),
                ("open-redirect", "SEC-08"), ("cors", "SEC-10"), ("jwt", "IDN-05"), ("hardcoded", "SEC-01"), ("secret", "SEC-01"),
                ("md5", "IDN-03"), ("sha1", "IDN-03"), ("debug", "SEC-15"), ("command-injection", "SEC-06"), ("injection", "SEC-06"))


def parse_semgrep(data) -> list[dict]:
    out = []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in (data or {}).get("results", []):
        rule = r.get("check_id", "semgrep")
        extra = r.get("extra") or {}
        ids = sorted({cid for key, cid in _SEMGREP_MAP if key in rule.lower()}) or ["SEC-06"]
        out.append(finding("semgrep", rule, sev_map.get(extra.get("severity"), "medium"), r.get("path", ""),
                           (r.get("start") or {}).get("line"), extra.get("message") or rule, ids))
    return out


# ---------------------------------------------------------------- runners

def _run(cmd, cwd, runner):
    return runner(cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS)


def _json_or_none(text):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def run_gitleaks(root: Path, runner=subprocess.run):
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        cmd = ["gitleaks", "detect", "--source", str(root), "--no-banner", "--redact",
               "--report-format", "json", "--report-path", str(report), "--exit-code", "0"]
        if not (root / ".git").exists():
            cmd.append("--no-git")
        proc = _run(cmd, root, runner)
        if proc.returncode != 0:
            return None, (proc.stderr or "gitleaks failed")[-300:]
        data = _json_or_none(report.read_text(encoding="utf-8")) if report.exists() else []
        return parse_gitleaks(data if data is not None else []), None


def run_osv(root: Path, runner=subprocess.run):
    for cmd in (["osv-scanner", "scan", "source", "--format", "json", "-r", str(root)],
                ["osv-scanner", "--format", "json", "-r", str(root)]):
        proc = _run(cmd, root, runner)  # exit code 1 means "vulnerabilities found"
        data = _json_or_none(proc.stdout)
        if data is not None:
            return parse_osv(data), None
    return None, "osv-scanner produced no JSON (no supported lockfiles found, or an incompatible version)"


def run_trivy(root: Path, runner=subprocess.run):
    cmd = ["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig", "--exit-code", "0", str(root)]
    proc = _run(cmd, root, runner)
    data = _json_or_none(proc.stdout)
    if proc.returncode != 0 or data is None:
        return None, (proc.stderr or "trivy failed")[-300:]
    return parse_trivy(data), None


def run_semgrep(root: Path, runner=subprocess.run):
    cmd = ["semgrep", "scan", "--config", "p/owasp-top-ten", "--config", "p/secrets", "--json", "--metrics=off", "--quiet", str(root)]
    proc = _run(cmd, root, runner)
    data = _json_or_none(proc.stdout)
    if data is None:
        return None, (proc.stderr or "semgrep failed")[-300:]
    return parse_semgrep(data), None


RUNNERS = {"gitleaks": run_gitleaks, "osv-scanner": run_osv, "trivy": run_trivy, "semgrep": run_semgrep}


def run_all(root: Path, tools, which=shutil.which, runner=subprocess.run) -> dict:
    result = {"root": str(root), "tools": {}}
    for tool in tools:
        if which(tool) is None:
            result["tools"][tool] = {"status": "missing", "install": INSTALL_HINTS[tool], "findings": []}
            continue
        try:
            findings, err = RUNNERS[tool](root, runner)
        except (subprocess.TimeoutExpired, OSError) as exc:
            findings, err = None, f"{type(exc).__name__}: {exc}"[:300]
        if findings is None:
            result["tools"][tool] = {"status": "failed", "error": err, "findings": []}
            continue
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        result["tools"][tool] = {
            "status": "ran", "counts": counts, "total": len(findings),
            "truncated": max(0, len(findings) - MAX_FINDINGS_PER_TOOL),
            "findings": findings[:MAX_FINDINGS_PER_TOOL],
        }
    ran = [t for t, v in result["tools"].items() if v["status"] == "ran"]
    result["summary"] = {"ran": ran,
                         "missing": [t for t, v in result["tools"].items() if v["status"] == "missing"],
                         "failed": [t for t, v in result["tools"].items() if v["status"] == "failed"]}
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--semgrep", action="store_true", help="also run semgrep (downloads rule packs)")
    args = ap.parse_args()

    tools = ["gitleaks", "osv-scanner", "trivy"] + (["semgrep"] if args.semgrep else [])
    result = run_all(args.root.resolve(), tools)
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    s = result["summary"]
    print(f"ran: {', '.join(s['ran']) or 'none'} | missing: {', '.join(s['missing']) or 'none'} | failed: {', '.join(s['failed']) or 'none'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
