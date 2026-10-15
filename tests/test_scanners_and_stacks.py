import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import detect_stacks as ds  # noqa: E402
import run_scanners as rs  # noqa: E402

FAKE_SECRET = "AKIAFAKEFAKEFAKE1234"
CHECKLIST = json.loads((ROOT / "checklist" / "checklist.json").read_text())
IDS = {i["id"] for d in CHECKLIST["domains"] for i in d["items"]}


class Normalisers(unittest.TestCase):
    def test_gitleaks_drops_secret_values(self):
        raw = [{"RuleID": "aws-access-token", "Description": "AWS key", "File": "src/a.js", "StartLine": 7,
                "Secret": FAKE_SECRET, "Match": f"key={FAKE_SECRET}", "Line": f"key={FAKE_SECRET}", "Commit": "abcdef1234567"}]
        out = rs.parse_gitleaks(raw)
        self.assertEqual(out[0]["file"], "src/a.js")
        self.assertEqual(out[0]["line"], 7)
        self.assertIn("SEC-01", out[0]["checklist"])
        self.assertIn("git history", out[0]["message"])
        self.assertNotIn(FAKE_SECRET, json.dumps(out))

    def test_trivy_secret_match_and_code_are_dropped(self):
        raw = {"Results": [{"Target": "app.env", "Secrets": [{"RuleID": "r", "Severity": "CRITICAL", "Title": "Stripe key",
                                                              "StartLine": 3, "Match": FAKE_SECRET, "Code": {"Lines": [FAKE_SECRET]}}],
                            "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "1", "Severity": "HIGH",
                                                 "FixedVersion": "2", "Title": "bad"}],
                            "Misconfigurations": [{"ID": "AVD-1", "Severity": "MEDIUM", "Title": "Open bucket",
                                                   "CauseMetadata": {"StartLine": 9}}]}]}
        out = rs.parse_trivy(raw)
        self.assertEqual({f["severity"] for f in out}, {"critical", "high", "medium"})
        self.assertNotIn(FAKE_SECRET, json.dumps(out))
        self.assertIn("fixed in 2", next(f for f in out if f["rule"] == "CVE-1")["message"])

    def test_osv_severity_from_groups(self):
        raw = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{
            "package": {"name": "lodash", "version": "4.0.0", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-1", "aliases": ["CVE-9"], "summary": "proto pollution"}],
            "groups": [{"ids": ["GHSA-1", "CVE-9"], "max_severity": "9.8"}]}]}]}
        out = rs.parse_osv(raw)
        self.assertEqual(out[0]["severity"], "critical")
        self.assertIn("lodash@4.0.0", out[0]["message"])

    def test_osv_missing_severity_defaults_to_medium(self):
        raw = {"results": [{"source": {"path": "x"}, "packages": [{
            "package": {"name": "a", "version": "1", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "V"}], "groups": []}]}]}
        self.assertEqual(rs.parse_osv(raw)[0]["severity"], "medium")

    def test_semgrep_maps_rules_to_checklist(self):
        raw = {"results": [{"check_id": "javascript.express.security.audit.xss.direct-response-write", "path": "a.js",
                            "start": {"line": 4}, "extra": {"severity": "ERROR", "message": "xss"}}]}
        out = rs.parse_semgrep(raw)
        self.assertEqual(out[0]["checklist"], ["SEC-05"])
        self.assertEqual(out[0]["severity"], "high")

    def test_empty_inputs(self):
        self.assertEqual(rs.parse_gitleaks(None), [])
        self.assertEqual(rs.parse_osv({}), [])
        self.assertEqual(rs.parse_trivy({"Results": [{"Target": "x"}]}), [])
        self.assertEqual(rs.parse_semgrep({}), [])

    def test_every_mapped_checklist_id_exists(self):
        mapped = {cid for _, cid in rs._SEMGREP_MAP} | {"SEC-01", "SEC-02", "SEC-04", "MNT-05", "SEC-12", "INF-02", "SEC-06"}
        self.assertFalse(mapped - IDS, mapped - IDS)


class Runner(unittest.TestCase):
    def test_missing_tools_are_reported_not_installed(self):
        called = []
        res = rs.run_all(Path("."), ["gitleaks", "trivy"], which=lambda t: None, runner=lambda *a, **k: called.append(a))
        self.assertEqual(res["summary"]["missing"], ["gitleaks", "trivy"])
        self.assertIn("install", res["tools"]["gitleaks"])
        self.assertEqual(called, [])

    def test_tool_run_and_failure_paths(self):
        def runner(cmd, **kw):
            if cmd[0] == "trivy":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"Results": []}), stderr="")
            return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="boom")
        res = rs.run_all(Path(tempfile.mkdtemp()), ["trivy", "gitleaks"], which=lambda t: "/bin/" + t, runner=runner)
        self.assertEqual(res["tools"]["trivy"]["status"], "ran")
        self.assertEqual(res["tools"]["gitleaks"]["status"], "failed")
        self.assertEqual(res["summary"]["ran"], ["trivy"])

    def test_gitleaks_command_is_redacted_and_non_failing(self):
        seen = {}
        def runner(cmd, **kw):
            seen["cmd"] = cmd
            Path(cmd[cmd.index("--report-path") + 1]).write_text("[]")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        rs.run_gitleaks(Path(tempfile.mkdtemp()), runner)
        self.assertIn("--redact", seen["cmd"])
        self.assertIn("--no-git", seen["cmd"])  # temp dir is not a git repo

    def test_findings_are_capped(self):
        many = [{"RuleID": "r", "File": "f", "StartLine": i} for i in range(rs.MAX_FINDINGS_PER_TOOL + 5)]
        def runner(cmd, **kw):
            Path(cmd[cmd.index("--report-path") + 1]).write_text(json.dumps(many))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        res = rs.run_all(Path(tempfile.mkdtemp()), ["gitleaks"], which=lambda t: "x", runner=runner)
        g = res["tools"]["gitleaks"]
        self.assertEqual(len(g["findings"]), rs.MAX_FINDINGS_PER_TOOL)
        self.assertEqual(g["truncated"], 5)


class StackDetection(unittest.TestCase):
    registry = json.loads((ROOT / "stacks" / "stacks.json").read_text())

    def detect(self, files):
        root = Path(tempfile.mkdtemp())
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return {d["id"] for d in ds.detect(root, self.registry)["detected"]}

    def test_dependencies_and_files(self):
        got = self.detect({"package.json": json.dumps({"dependencies": {"next": "14", "@supabase/supabase-js": "2"}})})
        self.assertEqual(got, {"nextjs", "supabase"})
        self.assertEqual(self.detect({"firestore.rules": "rules_version = '2';"}), {"firebase"})

    def test_content_match_and_nothing(self):
        self.assertEqual(self.detect({"src/pay.py": "stripe.Webhook.construct_event(a, b, c)"}), {"stripe"})
        self.assertEqual(self.detect({"README.md": "hello"}), set())

    def test_brace_glob(self):
        self.assertEqual(ds.expand_braces("**/*.{js,ts}"), ["**/*.js", "**/*.ts"])

    def test_fixtures(self):
        d1 = {d["id"] for d in ds.detect(ROOT / "examples" / "supabase-nextjs-app", self.registry)["detected"]}
        self.assertEqual(d1, {"supabase", "nextjs"})


class PlaybookIntegrity(unittest.TestCase):
    def test_registry_points_at_real_playbooks(self):
        reg = json.loads((ROOT / "stacks" / "stacks.json").read_text())
        for s in reg["stacks"]:
            self.assertTrue((ROOT / s["playbook"]).exists(), s["playbook"])
            self.assertTrue(s["detect"], s["id"])

    def test_every_playbook_is_registered(self):
        reg = {Path(s["playbook"]).name for s in json.loads((ROOT / "stacks" / "stacks.json").read_text())["stacks"]}
        on_disk = {p.name for p in (ROOT / "stacks").glob("*.md")}
        self.assertEqual(reg, on_disk)

    def test_maps_to_references_real_checklist_ids(self):
        for path in (ROOT / "stacks").glob("*.md"):
            text = path.read_text()
            found = re.findall(r"^Maps to: (.+)$", text, re.M)
            self.assertTrue(found, f"{path.name} has no 'Maps to:' lines")
            for line in found:
                for cid in (c.strip() for c in line.split(",")):
                    self.assertIn(cid, IDS, f"{path.name}: unknown checklist id {cid}")

    def test_every_check_has_a_maps_to_line(self):
        for path in (ROOT / "stacks").glob("*.md"):
            for section in re.split(r"^## ", path.read_text(), flags=re.M)[1:]:
                if re.match(r"[A-Z]{2}-\d", section):
                    self.assertRegex(section, r"Maps to: ", f"{path.name}: {section.splitlines()[0]}")

    def test_expected_findings_reference_real_ids(self):
        for fx in ("vibe-coded-app", "supabase-nextjs-app"):
            data = json.loads((ROOT / "examples" / fx / "expected-findings.json").read_text())
            for e in data["must_not_pass"]:
                self.assertIn(e["id"], IDS)


if __name__ == "__main__":
    unittest.main()
