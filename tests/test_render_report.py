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


class Waivers(unittest.TestCase):
    profile = {"stage": "launch", "tags": []}

    def test_active_waiver_closes_item(self):
        active, expired = rr.active_waivers({"AAA-01": {"reason": "r", "expires": "2026-06-01"}}, TODAY)
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "fail"}, ok("AAA-02")], active)
        self.assertEqual(rows["AAA-01"]["state"], "waived")
        self.assertEqual(rr.verdict_for(list(rows.values())), "READY")
        self.assertEqual(expired, {})

    def test_expired_waiver_reopens_item(self):
        active, expired = rr.active_waivers({"AAA-01": {"reason": "r", "expires": "2025-06-01"}}, TODAY)
        self.assertIn("AAA-01", expired)
        rows, _ = rows_for(self.profile, [{"id": "AAA-01", "status": "fail"}, ok("AAA-02")], active)
        self.assertEqual(rr.verdict_for(list(rows.values())), "NOT READY")

    def test_invalid_date_is_treated_as_expired(self):
        active, expired = rr.active_waivers({"AAA-01": {"reason": "r", "expires": "someday"}}, TODAY)
        self.assertIn("AAA-01", expired)


class EndToEnd(unittest.TestCase):
    def test_cli_writes_report_and_ci_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "findings").mkdir()
            (base / "profile.json").write_text(json.dumps({"project": "Acme", "stage": "launch", "tags": ["b2b"]}))
            (base / "findings" / "identity.json").write_text(
                json.dumps({"domain": "identity", "items": [
                    {"id": "IDN-06", "status": "fail", "evidence": ["src/login.ts:10"], "summary": "No limiter", "fix": "Add one"},
                    {"id": "IDN-02", "status": "pass", "evidence": ["src/reset.ts:5"]},
                ]})
            )
            cmd = [sys.executable, str(ROOT / "scripts" / "render_report.py"), "--dir", str(base), "--today", "2026-01-01"]
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
