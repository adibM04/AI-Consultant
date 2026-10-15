import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import render_report as rr  # noqa: E402

CHECKLIST = {
    "tags": ["b2b", "payments", "enterprise"],
    "roles": ["security"],
    "domains": [
        {
            "domain": "d",
            "title": "D",
            "summary": "s",
            "file": "x",
            "items": [
                {"id": "AAA-01", "title": "crit always", "severity": "critical", "tier": 1, "when": [], "evidence": "code", "role": "security", "check": "c"},
                {"id": "AAA-02", "title": "high always", "severity": "high", "tier": 1, "when": [], "evidence": "code", "role": "security", "check": "c"},
                {"id": "AAA-03", "title": "payments only", "severity": "critical", "tier": 1, "when": ["payments"], "evidence": "code", "role": "security", "check": "c"},
                {"id": "AAA-04", "title": "enterprise later", "severity": "high", "tier": 3, "when": [], "evidence": "process", "role": "security", "check": "c"},
            ],
        }
    ],
}
TODAY = dt.date(2026, 1, 1)


def rows_for(profile, findings, waivers=None):
    known = {"AAA-01", "AAA-02", "AAA-03", "AAA-04"}
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp) / "findings"
        d.mkdir()
        (d / "d.json").write_text(json.dumps({"domain": "d", "items": findings}))
        found, warns = rr.collect_findings(d, known)
    rows = rr.build_rows(CHECKLIST, profile, found, waivers or {})
    return {r["id"]: r for r in rows}, warns


def ok(i, **kw):
    return {"id": i, "status": "pass", "evidence": ["a.py:1"], **kw}


class Verdicts(unittest.TestCase):
    profile = {"stage": "launch", "tags": []}

    def verdict(self, findings, profile=None, waivers=None):
        rows, _ = rows_for(profile or self.profile, findings, waivers)
        return rr.verdict_for(list(rows.values()))

    def test_all_pass_is_ready(self):
        self.assertEqual(self.verdict([ok("AAA-01"), ok("AAA-02")]), "READY")

    def test_critical_fail_is_not_ready(self):
        self.assertEqual(self.verdict([{"id": "AAA-01", "status": "fail"}, ok("AAA-02")]), "NOT READY")

    def test_critical_partial_is_not_ready(self):
        self.assertEqual(self.verdict([{"id": "AAA-01", "status": "partial"}, ok("AAA-02")]), "NOT READY")

    def test_critical_unknown_is_not_verified(self):
        self.assertEqual(self.verdict([{"id": "AAA-01", "status": "unknown"}, ok("AAA-02")]), "NOT VERIFIED")

    def test_missing_critical_finding_is_not_verified(self):
        self.assertEqual(self.verdict([ok("AAA-02")]), "NOT VERIFIED")

    def test_high_fail_is_conditional(self):
        self.assertEqual(self.verdict([ok("AAA-01"), {"id": "AAA-02", "status": "fail"}]), "CONDITIONAL")

    def test_not_ready_beats_not_verified(self):
        v = self.verdict([{"id": "AAA-01", "status": "fail"}, {"id": "AAA-02", "status": "unknown"}])
        self.assertEqual(v, "NOT READY")


class Scope(unittest.TestCase):
    def test_tag_gating(self):
        rows, _ = rows_for({"stage": "launch", "tags": []}, [])
        self.assertEqual(rows["AAA-03"]["state"], "not-applicable")
        rows, _ = rows_for({"stage": "launch", "tags": ["payments"]}, [])
        self.assertEqual(rows["AAA-03"]["state"], "unaudited")

    def test_tier_gating(self):
        rows, _ = rows_for({"stage": "launch", "tags": []}, [])
        self.assertEqual(rows["AAA-04"]["state"], "later")
        rows, _ = rows_for({"stage": "enterprise", "tags": []}, [])
        self.assertEqual(rows["AAA-04"]["state"], "unaudited")

    def test_deferred_and_inapplicable_do_not_affect_verdict(self):
        rows, _ = rows_for({"stage": "launch", "tags": []}, [ok("AAA-01"), ok("AAA-02")])
        self.assertEqual(rr.verdict_for(list(rows.values())), "READY")


class Findings(unittest.TestCase):
    profile = {"stage": "launch", "tags": []}

    def test_pass_without_evidence_is_downgraded(self):
        rows, warns = rows_for(self.profile, [{"id": "AAA-01", "status": "pass"}])
        self.assertEqual(rows["AAA-01"]["state"], "unknown")
        self.assertTrue(any("without evidence" in w for w in warns))

    def test_na_without_reason_is_downgraded(self):
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "na"}])
        self.assertEqual(rows["AAA-01"]["state"], "unknown")

    def test_na_with_reason_is_not_counted(self):
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "na", "summary": "no passwords, SSO only"}, ok("AAA-02")])
        self.assertEqual(rows["AAA-01"]["state"], "na")
        self.assertEqual(rr.verdict_for(list(rows.values())), "READY")

    def test_unknown_id_and_bad_status_warn(self):
        rows, warns = rows_for(self.profile, [{"id": "ZZZ-99", "status": "pass"}, {"id": "AAA-02", "status": "great"}])
        self.assertTrue(any("ZZZ-99" in w for w in warns))
        self.assertEqual(rows["AAA-02"]["state"], "unknown")


SEV = {"AAA-01": "critical", "AAA-02": "high", "AAA-03": "critical", "AAA-04": "high"}


def waiver(**kw):
    base = {"reason": "r", "accepted_by": "Founder", "created": "2025-12-01", "expires": "2026-02-01"}
    return {**base, **kw}


class Waivers(unittest.TestCase):
    profile = {"stage": "launch", "tags": []}

    def test_valid_waiver_closes_item_but_critical_caps_verdict_at_conditional(self):
        active, expired, rejected = rr.active_waivers({"AAA-01": waiver(expires="2026-02-01")}, TODAY, SEV)
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "fail"}, ok("AAA-02")], active)
        self.assertEqual(rows["AAA-01"]["state"], "waived")
        self.assertEqual(rr.verdict_for(list(rows.values())), "CONDITIONAL")
        self.assertEqual((expired, rejected), ({}, {}))

    def test_waived_high_item_can_still_be_ready(self):
        active, _, _ = rr.active_waivers({"AAA-02": waiver(expires="2026-02-01")}, TODAY, SEV)
        rows, _ = rows_for(self.profile, [ok("AAA-01"), {"id": "AAA-02", "status": "fail"}], active)
        self.assertEqual(rr.verdict_for(list(rows.values())), "READY")

    def test_expired_waiver_reopens_item(self):
        active, expired, _ = rr.active_waivers({"AAA-01": waiver(created="2025-05-01", expires="2025-06-01")}, TODAY, SEV)
        self.assertIn("AAA-01", expired)
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "fail"}, ok("AAA-02")], active)
        self.assertEqual(rr.verdict_for(list(rows.values())), "NOT READY")

    def test_planted_waivers_are_rejected(self):
        planted = {
            "AAA-01": waiver(created="2025-12-01", expires="2099-01-01"),       # absurd horizon
            "AAA-02": waiver(accepted_by=""),                                   # nobody accepted it
            "AAA-03": waiver(reason=" "),                                       # no reason
            "AAA-04": {"reason": "r", "accepted_by": "x", "expires": "2026-02-01"},  # no created date
            "ZZZ-99": waiver(),                                                 # not a checklist item
        }
        active, expired, rejected = rr.active_waivers(planted, TODAY, SEV)
        self.assertEqual((active, expired), ({}, {}))
        self.assertEqual(set(rejected), set(planted))

    def test_critical_horizon_is_90_days_and_high_is_180(self):
        w = {"AAA-01": waiver(created="2025-12-01", expires="2026-03-15"),   # 104 days, critical
             "AAA-02": waiver(created="2025-12-01", expires="2026-03-15")}   # 104 days, high
        active, _, rejected = rr.active_waivers(w, TODAY, SEV)
        self.assertIn("AAA-01", rejected)
        self.assertIn("AAA-02", active)

    def test_future_created_and_bad_dates_are_rejected(self):
        _, _, rejected = rr.active_waivers({"AAA-01": waiver(created="2026-06-01", expires="2026-07-01"),
                                            "AAA-02": waiver(expires="someday")}, TODAY, SEV)
        self.assertEqual(set(rejected), {"AAA-01", "AAA-02"})


class EvidenceVerification(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "src").mkdir()
        (self.root / "src" / "auth.py").write_text("a\nb\nc\n")
        (self.root / ".consultant").mkdir()
        (self.root / ".consultant" / "note.md").write_text("x")

    def check(self, ref):
        return rr.evidence_resolves(ref, self.root)

    def test_resolution(self):
        self.assertTrue(self.check("src/auth.py"))
        self.assertTrue(self.check("src/auth.py:3"))
        self.assertFalse(self.check("src/auth.py:99"))     # line beyond end of file
        self.assertFalse(self.check("src/missing.py:1"))
        self.assertFalse(self.check("../etc/passwd"))      # escapes the project
        self.assertFalse(self.check("/etc/passwd"))
        self.assertFalse(self.check(".consultant/note.md"))  # the report's own output is not evidence
        self.assertFalse(self.check("searched: rate-limit|throttle"))
        self.assertFalse(self.check(""))

    def test_fabricated_pass_is_downgraded_when_root_given(self):
        d = Path(tempfile.mkdtemp())
        (d / "d.json").write_text(json.dumps({"domain": "d", "items": [
            {"id": "AAA-01", "status": "pass", "evidence": ["src/auth.py:2"]},
            {"id": "AAA-02", "status": "pass", "evidence": ["README.md:1", "totally/made/up.py:7"]},
        ]}))
        found, warns = rr.collect_findings(d, {"AAA-01", "AAA-02"}, root=self.root)
        self.assertEqual(found["AAA-01"]["status"], "pass")
        self.assertEqual(found["AAA-02"]["status"], "unknown")
        self.assertTrue(any("AAA-02" in w and "real file" in w for w in warns))

    def test_one_valid_reference_is_enough(self):
        d = Path(tempfile.mkdtemp())
        (d / "d.json").write_text(json.dumps({"domain": "d", "items": [
            {"id": "AAA-01", "status": "pass", "evidence": ["nope.py:1", "src/auth.py:1"]}]}))
        found, _ = rr.collect_findings(d, {"AAA-01"}, root=self.root)
        self.assertEqual(found["AAA-01"]["status"], "pass")


class EndToEnd(unittest.TestCase):
    def test_cli_writes_report_and_ci_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "findings").mkdir()
            (base / "src").mkdir()
            (base / "src" / "reset.ts").write_text("export const x = 1\n" * 10)
            (base / "profile.json").write_text(json.dumps({"project": "Acme", "stage": "launch", "tags": ["b2b"]}))
            (base / "findings" / "identity.json").write_text(
                json.dumps({"domain": "identity", "items": [
                    {"id": "IDN-06", "status": "fail", "evidence": ["src/login.ts:10"], "summary": "No limiter", "fix": "Add one"},
                    {"id": "IDN-02", "status": "pass", "evidence": ["src/reset.ts:5"]},
                ]})
            )
            cmd = [sys.executable, str(ROOT / "scripts" / "render_report.py"), "--dir", str(base), "--root", str(base),
                   "--today", "2026-01-01"]
            self.assertEqual(subprocess.run(cmd, capture_output=True, text=True).returncode, 0)
            report = (base / "REPORT.md").read_text()
            self.assertIn("Verdict: NOT READY", report)
            self.assertIn("IDN-06", report)
            self.assertIn("People this product still needs", report)
            self.assertEqual(subprocess.run(cmd + ["--ci"], capture_output=True, text=True).returncode, 1)
            # second run reports a diff against the first
            self.assertIn("Since the last run", (base / "REPORT.md").read_text())


class RealChecklist(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "checklist" / "checklist.json").read_text())

    def test_ids_unique(self):
        ids = [i["id"] for d in self.data["domains"] for i in d["items"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 150)

    def test_every_role_has_a_label(self):
        roles = {i["role"] for d in self.data["domains"] for i in d["items"]}
        self.assertFalse(roles - set(rr.ROLE_LABELS), roles - set(rr.ROLE_LABELS))

    def test_json_in_sync_with_yaml(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "checklist.py"), "build", "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
