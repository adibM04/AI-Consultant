#!/usr/bin/env python3
"""Keep ONE GitHub issue up to date with the advisories that affect this project.

GitHub emails everyone who watches the repository when an issue is created or commented on. So the
secret-free way to email a team is: create the issue once, refresh its body quietly, and add a comment
only when something NEW applies.

    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo python3 post_issue.py fetch-state --out state.json
    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo python3 post_issue.py publish --body body.md \\
                                                    --new new.md --result result.json

State between runs lives in a hidden comment at the end of the issue body (`<!-- seen: [...] -->`),
so the scheduled job needs no storage. Needs the `issues: write` permission. Degrades quietly where the
token is read-only (forked pull requests). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

MARKER = "<!-- ai-consultant-advisories -->"
SEEN = re.compile(r"<!-- seen: (\[.*?\]) -->", re.S)
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
DEFAULT_TITLE = "Security advisories affecting this project"


def request(method: str, url: str, token: str, payload: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ai-consultant-advisories",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else None


def find_issues(repo: str, token: str, call=request) -> list[dict]:
    """Issues (not pull requests) that carry our marker, newest first, open and closed."""
    found, page = [], 1
    while page <= 5:
        batch = call("GET", f"{API}/repos/{repo}/issues?state=all&per_page=100&page={page}&sort=created&direction=desc", token)
        found += [i for i in batch if "pull_request" not in i and MARKER in (i.get("body") or "")]
        if len(batch) < 100:
            break
        page += 1
    return found


def seen_keys(issue: dict | None) -> list[str]:
    if not issue:
        return []
    m = SEEN.search(issue.get("body") or "")
    try:
        keys = json.loads(m.group(1)) if m else []
    except json.JSONDecodeError:
        return []
    return [k for k in keys if isinstance(k, str)]


def build_body(body_md: str, keys: list[str]) -> str:
    stripped = SEEN.sub("", body_md).rstrip()
    if MARKER not in stripped:
        stripped = MARKER + "\n" + stripped
    return stripped + "\n\n<!-- seen: " + json.dumps(sorted(set(keys))) + " -->\n"


def publish(repo: str, token: str, body_md: str, new_md: str, result: dict, title: str = DEFAULT_TITLE, call=request) -> str:
    issues = find_issues(repo, token, call)
    open_issue = next((i for i in issues if i.get("state") == "open"), None)
    previous = seen_keys(issues[0] if issues else None)
    alerts = result.get("alerts", [])
    keys = previous + [a["key"] for a in alerts if "key" in a]
    has_new = any(a.get("new") for a in alerts)
    body = build_body(body_md, keys)

    if open_issue is None:
        if not has_new:
            return "nothing new and no open issue: left alone"
        call("POST", f"{API}/repos/{repo}/issues", token, {"title": title, "body": body})
        return "created"
    call("PATCH", f"{API}/repos/{repo}/issues/{open_issue['number']}", token, {"body": body})
    if has_new and new_md.strip():
        call("POST", f"{API}/repos/{repo}/issues/{open_issue['number']}/comments", token, {"body": new_md})
        return "updated and commented (this is what triggers the email)"
    return "updated quietly"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch-state")
    f.add_argument("--out", required=True, type=Path)
    p = sub.add_parser("publish")
    p.add_argument("--body", required=True, type=Path)
    p.add_argument("--new", type=Path)
    p.add_argument("--result", required=True, type=Path)
    p.add_argument("--title", default=DEFAULT_TITLE)
    args = ap.parse_args()

    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not (token and repo):
        print("post_issue: GITHUB_TOKEN / GITHUB_REPOSITORY not set, skipping")
        if args.cmd == "fetch-state":
            args.out.write_text("{}\n", encoding="utf-8")
        return 0
    try:
        if args.cmd == "fetch-state":
            issues = find_issues(repo, token)
            args.out.write_text(json.dumps({"seen": seen_keys(issues[0] if issues else None)}) + "\n", encoding="utf-8")
            print(f"post_issue: loaded {len(json.loads(args.out.read_text())['seen'])} previously seen advisories")
            return 0
        result = json.loads(args.result.read_text(encoding="utf-8"))
        new_md = args.new.read_text(encoding="utf-8") if args.new and args.new.exists() else ""
        print("post_issue: " + publish(repo, token, args.body.read_text(encoding="utf-8"), new_md, result, args.title))
    except urllib.error.HTTPError as exc:
        print(f"post_issue: could not reach the issues API (HTTP {exc.code}). Needs issues: write. Skipping.")
        if args.cmd == "fetch-state":
            args.out.write_text("{}\n", encoding="utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"post_issue: network error ({type(exc).__name__}), skipping")
        if args.cmd == "fetch-state" and not args.out.exists():
            args.out.write_text("{}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
