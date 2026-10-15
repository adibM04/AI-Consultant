import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import attest  # noqa: E402
import render_report as rr  # noqa: E402

TODAY = dt.date(2026, 10, 15)
ITEMS = {
    "DAT-08": {"id": "DAT-08", "evidence": "process", "severity": "critical"},
    "DAT-07": {"id": "DAT-07", "evidence": "config", "severity": "critical"},
    "SEC-06": {"id": "SEC-06", "evidence": "code", "severity": "critical"},
}


def project():
    root = Path(tempfile.mkdtemp())
    (root / "docs" / "evidence").mkdir(parents=True)
    (root / "docs" / "evidence" / "restore.md").write_text("Restored backup to staging. 14 minutes. Row counts matched.\n")
    return root


def att(**kw):
    base = {"attested_by": "Jane", "date": "2026-09-20", "expires": "2027-09-20", "note": "did it",
            "evidence": ["docs/evidence/restore.md"]}
    return {**base, **kw}


class Validation(unittest.TestCase):
    def check(self, mapping, root=None):
        return rr.active_attestations(mapping, TODAY, ITEMS, root or project())

    def test_valid_process_and_config_items_are_accepted(self):
        active, expired, rejected = self.check({"DAT-08": att(), "DAT-07": att()})
        self.assertEqual((set(active), expired, rejected), ({"DAT-08", "DAT-07"}, {}, {}))

    def test_code_checkable_items_cannot_be_attested(self):
        _, _, rejected = self.check({"SEC-06": att()})
        self.assertIn("checked in code", rejected["SEC-06"])

    def test_every_rejection_reason(self):
        root = project()
        bad = {
            "DAT-08": att(attested_by=" "),
            "DAT-07": att(date="2026-12-01", expires="2027-11-01"),          # future date
        }
        self.assertEqual(set(self.check(bad, root)[2]), {"DAT-08", "DAT-07"})
        cases = [att(expires="2028-09-21"),                                   # more than a year
                 att(expires="2026-09-20"),                                   # not after date
                 att(evidence=["docs/evidence/missing.md"]),                  # file does not exist
                 att(evidence=[]),
                 att(date="someday")]
        for c in cases:
            self.assertEqual(set(self.check({"DAT-08": c}, root)[2]), {"DAT-08"}, c)
        self.assertEqual(set(self.check({"ZZZ-01": att(), "DAT-08": "nope"}, root)[2]), {"ZZZ-01", "DAT-08"})

    def test_expired_attestation_is_reported_not_honoured(self):
        active, expired, rejected = self.check({"DAT-08": att(date="2025-01-01", expires="2025-12-31")})
        self.assertEqual((active, set(expired), rejected), ({}, {"DAT-08"}, {}))

    def test_evidence_inside_consultant_dir_is_not_accepted(self):
        root = project()
        (root / ".consultant").mkdir()
        (root / ".consultant" / "x.md").write_text("x")
        self.assertIn("DAT-08", self.check({"DAT-08": att(evidence=[".consultant/x.md"])}, root)[2])


class InReport(unittest.TestCase):
    def rows(self, findings, attestations):
        checklist = {"tags": [], "domains": [{"domain": "d", "title": "D", "summary": "", "file": "x", "items": [
            {"id": "DAT-08", "title": "restore tested", "severity": "critical", "tier": 1, "when": [], "evidence": "process", "role": "devops", "check": "c"},
            {"id": "SEC-06", "title": "injection", "severity": "critical", "tier": 1, "when": [], "evidence": "code", "role": "security", "check": "c"}]}]}
        return rr.build_rows(checklist, {"stage": "launch", "tags": []}, findings, {}, attestations)

    def test_attestation_settles_unknown_and_unaudited_only(self):
        a = {"DAT-08": att()}
        rows = {r["id"]: r for r in self.rows({}, a)}
        self.assertEqual(rows["DAT-08"]["state"], "attested")          # not audited at all
        rows = {r["id"]: r for r in self.rows({"DAT-08": {"id": "DAT-08", "status": "unknown"}}, a)}
        self.assertEqual(rows["DAT-08"]["state"], "attested")

    def test_attestation_never_overrides_a_failing_finding(self):
        rows = {r["id"]: r for r in self.rows({"DAT-08": {"id": "DAT-08", "status": "fail", "evidence": ["a:1"]}}, {"DAT-08": att()})}
        self.assertEqual(rows["DAT-08"]["state"], "fail")
        self.assertTrue(rows["DAT-08"]["attestation_ignored"])

    def test_attested_critical_does_not_block_ready_but_is_disclosed(self):
        rows = self.rows({"SEC-06": {"id": "SEC-06", "status": "pass", "evidence": ["a:1"]}}, {"DAT-08": att()})
        self.assertEqual(rr.verdict_for(rows), "READY")
        text, state = rr.render({"project": "p", "stage": "launch", "tags": []}, rows, [], {}, None, TODAY, {}, {},
                                ({}, {}))
        self.assertIn("relies on 1 item(s) settled by a person's attestation", text)
        self.assertIn("## Human attestations", text)
        self.assertEqual(state["statuses"]["DAT-08"], "attested")


class Cli(unittest.TestCase):
    def setUp(self):
        self.root = project()
        c = self.root / ".consultant"
        (c / "findings").mkdir(parents=True)
        (c / "profile.json").write_text(json.dumps({"project": "p", "stage": "launch", "tags": []}))
        self.base = [sys.executable, str(ROOT / "scripts" / "attest.py"), "--dir", str(c), "--root", str(self.root), "--today", "2026-10-15"]

    def run_cli(self, *args):
        return subprocess.run(self.base + list(args), capture_output=True, text=True)

    def add(self, item="DAT-08", evidence="docs/evidence/restore.md"):
        return self.run_cli("add", "--item", item, "--by", "Jane", "--note", "Restored it", "--evidence", evidence)

    def test_add_list_remove_roundtrip(self):
        r = self.add()
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads((self.root / ".consultant" / "attestations.json").read_text())
        self.assertEqual(data["DAT-08"]["expires"], "2027-10-15")
        self.assertIn("active   DAT-08", self.run_cli("list").stdout)
        self.assertEqual(self.run_cli("remove", "--item", "DAT-08").returncode, 0)
        self.assertEqual(self.run_cli("remove", "--item", "DAT-08").returncode, 1)

    def test_refuses_code_items_unknown_items_and_missing_files(self):
        self.assertEqual(self.add(item="SEC-06").returncode, 2)
        self.assertEqual(self.add(item="ZZZ-99").returncode, 2)
        self.assertEqual(self.add(evidence="docs/evidence/nope.md").returncode, 2)
        self.assertFalse((self.root / ".consultant" / "attestations.json").exists())

    def test_refuses_to_override_a_failing_finding(self):
        (self.root / ".consultant" / "findings" / "d.json").write_text(json.dumps({"domain": "data", "items": [
            {"id": "DAT-08", "status": "fail", "evidence": ["docs/evidence/restore.md"], "summary": "no restore"}]}))
        r = self.add()
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot override", r.stderr)

    def test_refuses_evidence_that_contains_secrets_and_never_prints_them(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        (self.root / "docs" / "evidence" / "leaky.md").write_text(f"output of env: AWS_KEY={secret}\n")
        r = self.add(evidence="docs/evidence/leaky.md")
        self.assertEqual(r.returncode, 2)
        self.assertIn("AWS access key", r.stderr)
        self.assertNotIn(secret, r.stdout + r.stderr)

    def test_secret_scanner_kinds(self):
        for text, kind in [("-----BEGIN RSA PRIVATE KEY-----", "private key block"),
                           ("postgres://admin:hunter22@db.example.com/x", "connection string with credentials"),
                           ("password = 'correct-horse'", "password assignment"),
                           ("sk_live_abcdefghij1234", "Stripe live key")]:
            p = self.root / "docs" / "evidence" / "t.md"
            p.write_text(text)
            self.assertIn(kind, attest.scan_for_secrets(p)[0], text)
        p.write_text("Restored fine. Password reset flow was also tested.")
        self.assertEqual(attest.scan_for_secrets(p)[0], [])

    def test_binary_evidence_is_accepted_with_a_warning(self):
        (self.root / "docs" / "evidence" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n\0\0data")
        r = self.add(evidence="docs/evidence/shot.png")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not scanned", r.stdout)

    def test_report_picks_up_the_attestation(self):
        self.add()
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "render_report.py"), "--dir", str(self.root / ".consultant"),
                            "--root", str(self.root), "--today", "2026-10-15"], capture_output=True, text=True)
        report = (self.root / ".consultant" / "REPORT.md").read_text()
        self.assertIn("Attested by Jane on 2026-10-15", report)


if __name__ == "__main__":
    unittest.main()
