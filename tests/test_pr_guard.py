import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import post_comment as pc  # noqa: E402
import pr_guard as pg  # noqa: E402

TODAY = dt.date(2026, 10, 15)
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def sh(root, *cmd):
    subprocess.run(cmd, cwd=root, check=True, capture_output=True, env=ENV)


def write(root, rel, content):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def commit(root, msg="c"):
    sh(root, "git", "add", "-A")
    sh(root, "git", "commit", "-q", "-m", msg, "--allow-empty")


def fake_fetch(table):
    def fetch(url, timeout=15.0):
        for needle, resp in table:
            if needle in url:
                return resp
        return 0, None
    return fetch


FETCH = fake_fetch([("registry.npmjs.org/made-up-zz", (404, None)),
                    ("registry.npmjs.org/axois", (200, {"time": {"created": "2019-01-01T00:00:00Z", "modified": "2019-01-01T00:00:00Z"},
                                                        "dist-tags": {"latest": "1"}, "versions": {"1": {}}}))])


def make_repo(findings=None, waivers=None, state=None, with_audit=True):
    root = Path(tempfile.mkdtemp())
    sh(root, "git", "init", "-q", "-b", "main")
    write(root, "server.js", "".join(f"line {i}\n" for i in range(1, 21)))
    write(root, "src/auth.py", "".join(f"a{i}\n" for i in range(1, 11)))
    write(root, "docs/policy.md", "policy\n")
    write(root, "package.json", json.dumps({"dependencies": {"express": "4"}}))
    if with_audit:
        items = findings or [
            {"id": "SEC-10", "status": "pass", "evidence": ["server.js:6-7"]},
            {"id": "IDN-02", "status": "pass", "evidence": ["src/auth.py:3"]},
            {"id": "AUT-02", "status": "pass", "evidence": ["docs/policy.md"]},
            {"id": "SEC-06", "status": "fail", "evidence": ["server.js:1"]},
        ]
        write(root, ".consultant/findings/security.json", json.dumps({"domain": "security", "items": items}))
        write(root, ".consultant/waivers.json", json.dumps(waivers if waivers is not None else {
            "SEC-16": {"reason": "r", "accepted_by": "F", "created": "2026-08-01", "expires": "2026-10-25"}}))
        write(root, ".consultant/state.json", json.dumps(state or {"verdict": "NOT READY"}))
    commit(root, "base")
    sh(root, "git", "checkout", "-q", "-b", "pr")
    return root


def kinds(result):
    return {x["kind"] for x in result["findings"]}


def guard(root, **kw):
    return pg.run(root, "main", "HEAD", offline=kw.pop("offline", False), fetch=FETCH, today=TODAY, **kw)


class Parsing(unittest.TestCase):
    def test_name_status_z_with_rename(self):
        raw = "M\0a.py\0D\0b.py\0R097\0old name.py\0new name.py\0A\0c.py\0"
        got = pg.parse_name_status(raw)
        self.assertEqual([c["status"] for c in got], ["M", "D", "R", "A"])
        self.assertEqual((got[2]["old"], got[2]["path"]), ("old name.py", "new name.py"))

    def test_hunks_and_overlap(self):
        diff = "@@ -5,2 +5,3 @@\n@@ -10,0 +11 @@\n@@ -20 +21 @@\n"
        h = pg.parse_old_ranges(diff)
        self.assertEqual(h, [(5, 6, False), (10, 10, True), (20, 20, False)])
        self.assertTrue(pg.overlaps((6, 7), h))        # touches line 6
        self.assertFalse(pg.overlaps((7, 9), h))
        self.assertTrue(pg.overlaps((9, 12), h))       # insertion after line 10 is inside the range
        self.assertFalse(pg.overlaps((10, 10), h))     # insertion after the last cited line is outside
        self.assertTrue(pg.overlaps((20, 20), h))


class Guard(unittest.TestCase):
    def test_clean_pr_has_no_findings(self):
        root = make_repo()
        write(root, "README.md", "hello\n")
        commit(root)
        r = guard(root)
        self.assertEqual(kinds(r) - {"waivers-expiring"}, set())
        self.assertEqual(r["passing_controls_tracked"], 3)

    def test_full_scenario(self):
        root = make_repo()
        content = (root / "server.js").read_text().replace("line 6\n", "line six changed\n")
        write(root, "server.js", content)                                  # edits a cited line
        sh(root, "git", "rm", "-q", "src/auth.py")                          # deletes cited evidence
        write(root, ".env", "KEY=value\n")
        write(root, ".env.example", "KEY=\n")                               # allowed
        write(root, "deploy/key.pem", "x\n")
        write(root, "package.json", json.dumps({"dependencies": {"express": "4", "made-up-zz": "1", "axois": "1"}}))
        write(root, ".consultant/waivers.json", json.dumps({"SEC-01": {"reason": "r", "accepted_by": "F",
                                                                       "created": "2026-09-01", "expires": "2099-01-01"}}))
        commit(root)
        r = guard(root)
        by_kind = {x["kind"]: x for x in r["findings"]}
        self.assertEqual(by_kind["evidence-deleted"]["items"], ["IDN-02"])
        self.assertEqual(by_kind["evidence-changed"]["items"], ["SEC-10"])
        self.assertNotIn("AUT-02", json.dumps(r["findings"]))              # untouched evidence is not flagged
        self.assertEqual(sorted(by_kind["secret-file"]["files"]), [".env", "deploy/key.pem"])
        self.assertIn("audit-record-changed", by_kind)
        self.assertEqual(by_kind["waivers-rejected"]["items"], ["SEC-01"])
        pkgs = [x for x in r["findings"] if x["kind"] == "new-package"]
        self.assertEqual(len(pkgs), 2)
        self.assertTrue(all(x["severity"] == "high" for x in pkgs))
        self.assertEqual(r["new_packages_checked"], 2)
        self.assertEqual(r["findings"][0]["severity"], "high")             # sorted by severity

    def test_edit_outside_cited_lines_is_ignored(self):
        root = make_repo()
        content = (root / "server.js").read_text().replace("line 15\n", "line fifteen\n")
        write(root, "server.js", content)
        commit(root)
        self.assertNotIn("evidence-changed", kinds(guard(root)))

    def test_rename_of_evidence_file_is_flagged(self):
        root = make_repo()
        sh(root, "git", "mv", "src/auth.py", "src/identity.py")
        commit(root)
        r = guard(root)
        self.assertEqual([x for x in r["findings"] if x["kind"] == "evidence-changed"][0]["items"], ["IDN-02"])

    def test_pr_cannot_approve_itself_by_editing_the_audit_record(self):
        """The baseline is read from the base ref: findings added in the PR are not trusted."""
        root = make_repo(findings=[{"id": "SEC-06", "status": "fail", "evidence": ["server.js:1"]}])
        write(root, ".consultant/findings/security.json", json.dumps({"domain": "security", "items": [
            {"id": "SEC-06", "status": "pass", "evidence": ["README.md:1"]}]}))
        sh(root, "git", "rm", "-q", "server.js")
        commit(root)
        r = guard(root)
        self.assertEqual(r["passing_controls_tracked"], 0)
        self.assertNotIn("evidence-deleted", kinds(r))          # nothing passed on the base, so nothing was lost
        self.assertIn("audit-record-changed", kinds(r))          # but the edit itself is surfaced

    def test_no_baseline_audit(self):
        root = make_repo(with_audit=False)
        write(root, "x.txt", "x")
        commit(root)
        self.assertIn("no-baseline", kinds(guard(root)))

    def test_stale_audit(self):
        base_sha = None
        root = make_repo(state={"verdict": "NOT READY"})
        base_sha = subprocess.run(["git", "rev-parse", "main"], cwd=root, capture_output=True, text=True).stdout.strip()
        sh(root, "git", "checkout", "-q", "main")
        write(root, ".consultant/state.json", json.dumps({"verdict": "NOT READY", "commit": base_sha}))
        commit(root, "record audit commit")
        sh(root, "git", "checkout", "-q", "pr")
        sh(root, "git", "merge", "-q", "--no-edit", "main")
        old, pg.STALE_COMMITS = pg.STALE_COMMITS, 1
        try:
            for i in range(3):
                commit(root, f"more {i}")
            self.assertIn("stale-audit", kinds(guard(root)))
        finally:
            pg.STALE_COMMITS = old

    def test_offline_skips_registry_but_catches_typosquats(self):
        root = make_repo()
        write(root, "package.json", json.dumps({"dependencies": {"express": "4", "axois": "1", "made-up-zz": "1"}}))
        commit(root)

        def boom(*a, **k):
            raise AssertionError("network used")
        r = pg.run(root, "main", "HEAD", offline=True, fetch=boom, today=TODAY)
        titles = " ".join(x["title"] for x in r["findings"] if x["kind"] == "new-package")
        self.assertIn("axois", titles)
        self.assertNotIn("made-up-zz", titles)

    def test_secret_file_contents_are_never_read_or_printed(self):
        root = make_repo()
        write(root, ".env", "TOPSECRET_VALUE_12345\n")
        commit(root)
        r = guard(root)
        self.assertNotIn("TOPSECRET_VALUE_12345", json.dumps(r) + pg.to_markdown(r))

    def test_cli_exit_codes(self):
        root = make_repo()
        write(root, ".env", "A=1\n")
        commit(root)
        cmd = [sys.executable, str(ROOT / "scripts" / "pr_guard.py"), "--base", "main", "--root", str(root), "--offline"]
        self.assertEqual(subprocess.run(cmd, capture_output=True, text=True).returncode, 1)
        self.assertEqual(subprocess.run(cmd + ["--fail-on", "none"], capture_output=True, text=True).returncode, 0)
        bad = subprocess.run(cmd[:-3] + ["--base", "nope", "--root", str(root)], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)
        self.assertIn("fetch-depth", bad.stderr)


class Markdown(unittest.TestCase):
    def test_hostile_file_names_cannot_inject_markup(self):
        nasty = "x`<img src=x onerror=alert(1)>`\n[click](http://evil.invalid)|.env"
        out = pg.to_markdown({"changed_files": 1, "new_packages_checked": 0, "passing_controls_tracked": 0, "findings": [
            pg.f("high", "secret-file", "t`itle\n# injected heading", "detail <script>", files=[nasty], items=["A`B"])]})
        self.assertTrue(out.startswith(pg.MARKER))
        body = out.split("<sub>")[0]          # the footer carries our own legitimate link
        for bad in ("<img", "<script", "\n# injected", "](http"):
            self.assertNotIn(bad, body)

    def test_our_own_help_text_survives_sanitising(self):
        """Real-runner output showed backticks and <ids> stripped from fixed help text."""
        root = make_repo()
        content = (root / "server.js").read_text().replace("line 6\n", "line six changed\n")
        write(root, "server.js", content)
        commit(root)
        md = pg.to_markdown(guard(root))
        self.assertIn("/ai-consultant:consult-audit followed by the control ids", md)
        self.assertNotIn("  ids  ", md)
        root2 = make_repo(with_audit=False)
        write(root2, "x.txt", "x")
        commit(root2)
        self.assertIn("commit the .consultant folder", pg.to_markdown(guard(root2)))

    def test_pr_text_cannot_form_workflow_commands_in_the_log(self):
        out = pg.to_markdown({"changed_files": 1, "new_packages_checked": 0, "passing_controls_tracked": 0, "findings": [
            pg.f("medium", "waivers-rejected", "t", "::error::fake ::add-mask::x ##[warning]hi", items=["::set-output name=a::b"],
                 files=["::stop-commands::tok"])]})
        for line in out.splitlines():
            self.assertFalse(line.strip().startswith(("::", "##[")), line)   # "### Heading" is ours and harmless; "##[" is the runner syntax
        self.assertNotIn("::error::", out)
        self.assertNotIn("##[", out)

    def test_clean_report_says_so(self):
        out = pg.to_markdown({"changed_files": 3, "new_packages_checked": 1, "passing_controls_tracked": 5, "findings": []})
        self.assertIn("no issues found", out)


class Comment(unittest.TestCase):
    def test_create_then_update_sticky_comment(self):
        calls = []
        store = [{"id": 1, "body": "unrelated"}]

        def call(method, url, token, payload=None):
            calls.append((method, url.split("/repos/")[1]))
            if method == "GET":
                return list(store)
            if method == "POST":
                store.append({"id": 2, "body": payload["body"]})
            return {}
        self.assertEqual(pc.upsert("o/r", 7, pc.MARKER + "\nhi", "t", call), "created")
        self.assertEqual(pc.upsert("o/r", 7, pc.MARKER + "\nhi again", "t", call), "updated")
        self.assertIn(("PATCH", "o/r/issues/comments/2"), calls)

    def test_pagination(self):
        pages = {1: [{"id": i, "body": "x"} for i in range(100)], 2: [{"id": 500, "body": pc.MARKER}]}

        def call(method, url, token, payload=None):
            if method == "GET":
                return pages[int(url.rsplit("page=", 1)[1])]
            return {}
        self.assertEqual(pc.upsert("o/r", 1, pc.MARKER, "t", call), "updated")

    def test_missing_env_and_non_pr_events_skip_quietly(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "post_comment.py"), "x.md"], capture_output=True, text=True,
                           env={k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")})
        self.assertEqual(r.returncode, 0)
        self.assertIn("skipping", r.stdout)


class Packaging(unittest.TestCase):
    def test_action_and_templates_are_valid(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        action = yaml.safe_load((ROOT / "action.yml").read_text())
        self.assertEqual(action["runs"]["using"], "composite")
        self.assertEqual(set(action["inputs"]), {"base-ref", "fail-on", "offline", "comment"})
        for t in ("pr-guard.yml", "weekly-audit.yml"):
            wf = yaml.safe_load((ROOT / "templates" / t).read_text())
            self.assertIn("permissions", wf)
        weekly = yaml.safe_load((ROOT / "templates" / "weekly-audit.yml").read_text())
        triggers = set(weekly[True])  # PyYAML parses the key `on` as boolean True
        self.assertEqual(triggers, {"schedule", "workflow_dispatch"})   # never pull_request
        guard_wf = yaml.safe_load((ROOT / "templates" / "pr-guard.yml").read_text())
        self.assertNotIn("pull_request_target", guard_wf[True])

    def test_pinned_release_matches_plugin_version(self):
        """Docs and templates pin the release: by tag `vX.Y.Z`, or by a full commit SHA annotated `# vX.Y.Z`."""
        import re
        version = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())["version"]
        tag = re.escape(f"v{version}")
        pin = re.compile(r"adibM04/AI-Consultant@(?:" + tag + r"\b|[0-9a-f]{40}\s+# " + tag + r"\b)")
        for f in ("templates/pr-guard.yml", "docs/ci.md"):
            self.assertRegex((ROOT / f).read_text(), pin, f)
        ref = re.compile(r"ref: (?:" + tag + r"\b|[0-9a-f]{40}\s+# release " + tag + r"\b)")
        self.assertRegex((ROOT / "templates" / "weekly-audit.yml").read_text(), ref)
        for f in ("README.md", "docs/ci.md", "templates/pr-guard.yml", "templates/weekly-audit.yml"):
            self.assertNotIn("AI-Consultant@main", (ROOT / f).read_text(), f)
        self.assertIn(f"## {version}", (ROOT / "CHANGELOG.md").read_text())

    def test_action_script_still_reports_and_comments_when_the_guard_blocks(self):
        """Regression: GitHub runs the step with `bash -e`; a blocking exit code used to abort the script before
        the job summary and the PR comment. Run the real step under the runner's exact flags."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        import shutil
        if not shutil.which("bash"):
            self.skipTest("bash not available")
        script = yaml.safe_load((ROOT / "action.yml").read_text())["runs"]["steps"][0]["run"]
        root = make_repo()
        write(root, ".env", "A=1\n")
        commit(root)
        sh(root, "git", "update-ref", "refs/remotes/origin/main", "main")
        out = Path(tempfile.mkdtemp())
        summary = out / "summary.md"
        event = out / "event.json"
        event.write_text(json.dumps({"pull_request": {"number": 7}}))
        env = {**os.environ, "ACTION_PATH": str(ROOT), "INPUT_BASE_REF": "", "INPUT_FAIL_ON": "high", "INPUT_OFFLINE": "true",
               "INPUT_COMMENT": "true", "BASE_BRANCH": "main", "GH_TOKEN": "", "RUNNER_TEMP": str(out),
               "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": "o/r"}
        proc = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script], cwd=root, env=env,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)          # the job still fails, as intended
        self.assertIn("blocking", proc.stdout)
        self.assertIn("::endgroup::", proc.stdout)                               # the log group is closed
        self.assertTrue(summary.exists() and ".env" in summary.read_text())      # the job summary was written
        self.assertIn("post_comment:", proc.stdout)                              # and the comment step ran (it skips without a token)
        self.assertIn("::error::AI-Consultant PR guard reported blocking findings", proc.stdout)

    def test_weekly_template_keeps_its_safety_properties(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        text = (ROOT / "templates" / "weekly-audit.yml").read_text()
        wf = yaml.safe_load(text)
        self.assertEqual(set(wf[True]), {"schedule", "workflow_dispatch"})
        self.assertEqual(wf["permissions"], {"contents": "read"})
        steps = wf["jobs"]["audit"]["steps"]
        names = [st.get("name", "") for st in steps]
        move = names.index("Move the plugin out of the audited workspace")
        audit = names.index("Run the audit")
        self.assertLess(move, audit)                                   # moved before the model runs
        self.assertLess(names.index("Require the API key"), audit)     # a missing key fails with a plain message first
        self.assertIn("claude.err", steps[audit]["run"])               # and a failed run shows why
        self.assertIn("$RUNNER_TEMP/ai-consultant", steps[move]["run"])
        for st in steps:                                               # inputs reach the shell only through env
            run = st.get("run", "")
            self.assertNotIn("${{", run, st.get("name"))
        env = steps[audit]["env"]
        self.assertIn("INPUT_DOMAINS", env)
        self.assertIn("INPUT_BUDGET", env)
        run = steps[audit]["run"]
        self.assertIn("--max-budget-usd", run)                         # hard spending cap
        self.assertIn("max-budget-usd must be a number", run)          # validated inputs
        self.assertIn("domains may only contain", run)
        self.assertIn("--plugin-dir \"$plugin\"", run)               # plugin outside the workspace
        self.assertNotIn(".ai-consultant", " ".join(st.get("run", "") for st in steps[audit:]))  # nothing reads it from inside
        self.assertIn("DEDICATED key", text)                           # the key-exfiltration warning stays

    def test_action_does_not_interpolate_inputs_into_shell(self):
        text = (ROOT / "action.yml").read_text()
        run_block = text.split("run: |", 1)[1]
        self.assertNotIn("${{", run_block)   # inputs reach the shell only through env vars


if __name__ == "__main__":
    unittest.main()
