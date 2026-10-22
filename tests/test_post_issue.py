import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import post_issue as pi  # noqa: E402

BODY = pi.MARKER + "\n### Security advisories affecting this project\n- lodash\n"


class FakeGitHub:
    def __init__(self, issues=None):
        self.issues = issues or []
        self.calls = []

    def __call__(self, method, url, token, payload=None):
        self.calls.append((method, url.split("/repos/")[1] if "/repos/" in url else url, payload))
        if method == "GET":
            return list(self.issues)
        if method == "POST" and url.endswith("/issues"):
            self.issues.insert(0, {"number": 7, "state": "open", **payload})
        if method == "PATCH":
            self.issues[0]["body"] = payload["body"]
        return {}

    def verbs(self):
        return [(m, "comment" if "comments" in u else "issue") for m, u, _ in self.calls if m != "GET"]


def result(*alerts):
    return {"alerts": [{"key": k, "new": new} for k, new in alerts]}


class Publish(unittest.TestCase):
    def test_creates_the_issue_once_when_something_new_applies(self):
        gh = FakeGitHub()
        self.assertEqual(pi.publish("o/r", "t", BODY, "new text", result(("k1", True)), call=gh), "created")
        self.assertEqual(gh.verbs(), [("POST", "issue")])
        created = gh.issues[0]
        self.assertIn(pi.MARKER, created["body"])
        self.assertEqual(pi.seen_keys(created), ["k1"])                       # state survives in the body

    def test_no_issue_is_created_when_nothing_is_new(self):
        gh = FakeGitHub()
        self.assertIn("left alone", pi.publish("o/r", "t", BODY, "", result(("k1", False)), call=gh))
        self.assertEqual(gh.verbs(), [])
        self.assertIn("left alone", pi.publish("o/r", "t", BODY, "", result(), call=FakeGitHub()))

    def test_refresh_is_quiet_unless_new_and_new_triggers_one_comment(self):
        existing = {"number": 7, "state": "open", "body": pi.build_body(BODY, ["k1"])}
        gh = FakeGitHub([existing])
        self.assertEqual(pi.publish("o/r", "t", BODY, "", result(("k1", False)), call=gh), "updated quietly")
        self.assertEqual(gh.verbs(), [("PATCH", "issue")])                    # body edit: no email
        gh = FakeGitHub([{**existing}])
        out = pi.publish("o/r", "t", BODY, "### New: k2", result(("k1", False), ("k2", True)), call=gh)
        self.assertIn("commented", out)
        self.assertEqual(gh.verbs(), [("PATCH", "issue"), ("POST", "comment")])
        self.assertEqual(sorted(pi.seen_keys(gh.issues[0])), ["k1", "k2"])    # k2 remembered: reported once

    def test_closed_issue_keeps_state_and_new_alerts_open_a_fresh_one(self):
        closed = {"number": 3, "state": "closed", "body": pi.build_body(BODY, ["old"])}
        gh = FakeGitHub([closed])
        self.assertEqual(pi.publish("o/r", "t", BODY, "n", result(("old", False), ("fresh", True)), call=gh), "created")
        self.assertEqual(sorted(pi.seen_keys(gh.issues[0])), ["fresh", "old"])   # 'old' is not announced again
        self.assertEqual(pi.publish("o/r", "t", BODY, "", result(("old", False)), call=FakeGitHub([closed])).split(":")[0], "nothing new and no open issue")

    def test_only_our_issues_count_and_pull_requests_are_ignored(self):
        gh = FakeGitHub([{"number": 1, "state": "open", "body": "unrelated"},
                         {"number": 2, "state": "open", "body": pi.MARKER, "pull_request": {}},
                         {"number": 3, "state": "open", "body": pi.build_body(BODY, ["x"])}])
        self.assertEqual([i["number"] for i in pi.find_issues("o/r", "t", gh)], [3])

    def test_seen_state_helpers(self):
        self.assertEqual(pi.seen_keys(None), [])
        self.assertEqual(pi.seen_keys({"body": "<!-- seen: not json -->"}), [])
        body = pi.build_body(BODY + "<!-- seen: [\"stale\"] -->", ["a", "a", "b"])
        self.assertEqual(body.count("<!-- seen:"), 1)                          # replaced, never duplicated
        self.assertEqual(pi.seen_keys({"body": body}), ["a", "b"])


class Cli(unittest.TestCase):
    def run_cli(self, *args, env=None):
        base = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "post_issue.py"), *args], capture_output=True, text=True, env={**base, **(env or {})})

    def test_skips_quietly_without_credentials_and_still_writes_state(self):
        out = Path(tempfile.mkdtemp()) / "state.json"
        r = self.run_cli("fetch-state", "--out", str(out))
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipping", r.stdout)
        self.assertEqual(json.loads(out.read_text()), {})                     # the next step still has a state file to read


class Template(unittest.TestCase):
    def test_workflow_is_secret_free_and_never_runs_on_pull_requests(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        text = (ROOT / "templates" / "advisory-watch.yml").read_text()
        wf = yaml.safe_load(text)
        self.assertEqual(set(wf[True]), {"schedule", "workflow_dispatch"})
        self.assertEqual(wf["permissions"], {"contents": "read", "issues": "write"})
        self.assertNotIn("secrets.", text)                                    # only the built-in token
        steps = wf["jobs"]["watch"]["steps"]
        names = [s.get("name", "") for s in steps]
        self.assertLess(names.index("Move the plugin out of the scanned workspace"), names.index("Check the feeds"))
        for s in steps:
            self.assertNotIn("${{", s.get("run", ""), s.get("name"))           # expressions reach the shell only through env


if __name__ == "__main__":
    unittest.main()
