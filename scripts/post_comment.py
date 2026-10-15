#!/usr/bin/env python3
"""Create or update one sticky pull-request comment (identified by a hidden marker).

    GITHUB_TOKEN=... GITHUB_REPOSITORY=o/r GITHUB_EVENT_PATH=event.json python3 post_comment.py guard.md

Exits 0 even when it cannot post (forked PRs get a read-only token; that is normal), and says so.
Standard library only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

MARKER = "<!-- ai-consultant-pr-guard -->"
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def request(method: str, url: str, token: str, payload: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(payload).encode() if payload is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "ai-consultant-pr-guard",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        return json.loads(body) if body else None


def find_existing(comments: list[dict], marker: str = MARKER):
    for c in comments:
        if marker in (c.get("body") or ""):
            return c
    return None


def upsert(repo: str, pr: int, body: str, token: str, call=request) -> str:
    base = f"{API}/repos/{repo}/issues"
    comments, page = [], 1
    while page <= 10:
        batch = call("GET", f"{base}/{pr}/comments?per_page=100&page={page}", token)
        comments += batch
        if len(batch) < 100:
            break
        page += 1
    existing = find_existing(comments)
    if existing:
        call("PATCH", f"{base}/comments/{existing['id']}", token, {"body": body})
        return "updated"
    call("POST", f"{base}/{pr}/comments", token, {"body": body})
    return "created"


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: post_comment.py <markdown-file>")
    token, repo, event_path = (os.environ.get(k) for k in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"))
    if not (token and repo and event_path):
        print("post_comment: GITHUB_TOKEN / GITHUB_REPOSITORY / GITHUB_EVENT_PATH not set, skipping")
        return 0
    with open(event_path, encoding="utf-8") as fh:
        event = json.load(fh)
    pr = (event.get("pull_request") or {}).get("number")
    if not pr:
        print("post_comment: not a pull_request event, skipping")
        return 0
    body = open(sys.argv[1], encoding="utf-8").read()
    if MARKER not in body:
        sys.exit("refusing to post: markdown has no marker")
    try:
        print(f"post_comment: {upsert(repo, int(pr), body, token)}")
    except urllib.error.HTTPError as exc:
        print(f"post_comment: could not post (HTTP {exc.code}). Normal on forked PRs; see the job summary instead.")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"post_comment: network error ({type(exc).__name__}), skipping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
