import datetime as dt
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import advisories as adv  # noqa: E402

TODAY = dt.date(2026, 10, 22)


def project(files: dict) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return root


class FakeNet:
    """Stand-in for the three feeds. `down` lists feeds that fail."""

    def __init__(self, osv=None, vulns=None, kev=None, eol=None, down=()):
        self.osv, self.vulns, self.kev, self.eol, self.down = osv or {}, vulns or {}, kev or [], eol or {}, set(down)
        self.calls = []

    def __call__(self, method, url, body=None, timeout=15.0):
        self.calls.append(url)
        if url.startswith(adv.OSV_BATCH):
            if "osv" in self.down:
                return 0, None
            return 200, {"results": [{"vulns": [{"id": i} for i in self.osv.get((q["package"]["name"], q["version"]), [])]} for q in body["queries"]]}
        if url.startswith(adv.OSV_VULN):
            v = self.vulns.get(url.rsplit("/", 1)[1])
            return (200, v) if v else (404, None)
        if url == adv.KEV_URL:
            return (0, None) if "kev" in self.down else (200, {"vulnerabilities": self.kev})
        if url.startswith("https://endoflife.date/api/"):
            product = url.rsplit("/", 1)[1].removesuffix(".json")
            return (0, None) if "eol" in self.down or product not in self.eol else (200, self.eol[product])
        return 0, None


PHP_CYCLES = [{"cycle": "8.4", "eol": "2028-12-31"}, {"cycle": "8.3", "eol": "2027-12-31"}, {"cycle": "8.2", "eol": "2026-12-31"},
              {"cycle": "8.1", "eol": "2025-12-31"}, {"cycle": "7.4", "eol": "2022-11-28"}]
LODASH_VULN = {"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "aliases": ["CVE-2020-8203"],
               "database_specific": {"severity": "HIGH"}, "published": "2020-07-15T00:00:00Z",
               "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]}
LOCK = {"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.15"},
                                          "node_modules/a/node_modules/b": {"version": "1.0.0"}, "node_modules/linked": {"version": "1.0.0", "link": True}}}


class Parsing(unittest.TestCase):
    def test_package_lock_v3_and_v1(self):
        self.assertEqual(sorted(adv.parse_package_lock(json.dumps(LOCK))), [("b", "1.0.0"), ("lodash", "4.17.15")])
        v1 = {"dependencies": {"x": {"version": "2.0.0", "dependencies": {"y": {"version": "3.0.0"}}}}}
        self.assertEqual(sorted(adv.parse_package_lock(json.dumps(v1))), [("x", "2.0.0"), ("y", "3.0.0")])
        self.assertEqual(adv.parse_package_lock("not json"), [])

    def test_composer_lock_skips_dev_branches(self):
        lock = {"packages": [{"name": "symfony/http-kernel", "version": "v5.4.1"}, {"name": "acme/x", "version": "dev-main"}],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}
        self.assertEqual(adv.parse_composer_lock(json.dumps(lock)), [("symfony/http-kernel", "5.4.1"), ("phpunit/phpunit", "9.5.0")])

    def test_requirements_pins_only(self):
        text = "Django==2.2.0\nflask>=2\nRequests[security]==2.19.0 ; python_version>'3'  # c\n-r other.txt\nnumpy~=1.0\n"
        self.assertEqual(adv.parse_requirements_pins(text), [("django", "2.2.0"), ("requests", "2.19.0")])

    def test_version_cycles(self):
        self.assertEqual(adv.lowest_cycle("^8.1 || ^8.3", 2), "8.1")
        self.assertEqual(adv.lowest_cycle(">=7.4", 2), "7.4")
        self.assertEqual(adv.lowest_cycle("^20", 1), "20")
        self.assertEqual(adv.lowest_cycle("*", 2), None)
        self.assertEqual(adv.cycle_of("8.3.12", 2), "8.3")
        self.assertEqual(adv.cycle_of("v20.11.0", 1), "20")

    def test_runtime_detection(self):
        root = project({
            "composer.json": {"require": {"php": "^8.1", "laravel/framework": "^10"}},
            "Dockerfile": "FROM php:8.3-fpm-alpine AS base\nFROM node:20 AS build\n",
            ".nvmrc": "v18.19.0\n", ".python-version": "3.11.4\n",
            "node_modules/x/package.json": {"engines": {"node": ">=4"}},   # vendored: ignored
        })
        got = {(r["product"], r["cycle"], r["exact"]) for r in adv.detect_runtimes(root)}
        self.assertEqual(got, {("php", "8.1", False), ("php", "8.3", True), ("node", "20", True), ("node", "18", True), ("python", "3.11", True)})

    def test_inventory_counts_unpinned_including_composer(self):
        root = project({"package-lock.json": LOCK, "package.json": {"dependencies": {"lodash": "^4", "left-pad": "^1"}},
                        "composer.json": {"require": {"php": "^8.1", "ext-json": "*", "acme/lib": "^1"}}})
        inv = adv.inventory(root)
        self.assertIn("npm:left-pad", inv["unpinned"])
        self.assertIn("packagist:acme/lib", inv["unpinned"])
        self.assertNotIn("npm:lodash", inv["unpinned"])
        self.assertFalse([u for u in inv["unpinned"] if "ext-json" in u])


class Severity(unittest.TestCase):
    def test_cvss3_known_scores(self):
        self.assertEqual(adv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(adv.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(adv.cvss3_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertIsNone(adv.cvss3_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"))
        self.assertIsNone(adv.cvss3_score("garbage"))

    def test_label_prefers_database_label_then_vector(self):
        self.assertEqual(adv.severity_label({"database_specific": {"severity": "MODERATE"}}), "MEDIUM")
        self.assertEqual(adv.severity_label({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}), "CRITICAL")
        self.assertEqual(adv.severity_label({}), "UNKNOWN")


class Collect(unittest.TestCase):
    def run_collect(self, files, net):
        return adv.collect(project(files), adv.Feeds(net), TODAY)

    def test_exploited_package_vulnerability_ranks_first_and_dedupes_aliases(self):
        net = FakeNet(osv={("lodash", "4.17.15"): ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"]},
                      vulns={"GHSA-p6mc-m468-83gw": LODASH_VULN,
                             "CVE-2020-8203": {**LODASH_VULN, "id": "CVE-2020-8203", "aliases": ["GHSA-p6mc-m468-83gw"]}},
                      kev=[{"cveID": "CVE-2020-8203", "vendorProject": "lodash", "product": "lodash", "dateAdded": "2022-01-01"}])
        r = self.run_collect({"package-lock.json": LOCK}, net)
        vulns = [a for a in r["alerts"] if a["kind"] == "package-vuln"]
        self.assertEqual(len(vulns), 1)                                    # alias pair reported once
        self.assertEqual(vulns[0]["priority"], 0)
        self.assertTrue(vulns[0]["exploited"])
        self.assertEqual(vulns[0]["fixed_in"], ["4.17.19"])
        self.assertIn("Upgrade lodash to 4.17.19", vulns[0]["action"])
        self.assertEqual(r["coverage"]["packages_checked"], 2)

    def test_withdrawn_and_unknown_details_are_skipped(self):
        net = FakeNet(osv={("lodash", "4.17.15"): ["GHSA-w", "GHSA-missing"]}, vulns={"GHSA-w": {**LODASH_VULN, "id": "GHSA-w", "withdrawn": "2021-01-01"}})
        self.assertEqual(self.run_collect({"package-lock.json": LOCK}, net)["alerts"], [])

    def test_end_of_life_past_soon_and_supported(self):
        net = FakeNet(eol={"php": PHP_CYCLES})
        past = self.run_collect({"composer.json": {"require": {"php": ">=7.4"}}}, net)["alerts"]
        self.assertEqual((past[0]["kind"], past[0]["priority"]), ("runtime-eol", 1))
        self.assertIn("lowest version your project declares", past[0]["title"])
        self.assertIn("newest supported: 8.4", past[0]["action"])
        soon = self.run_collect({".php-version": "8.2.5"}, net)["alerts"]
        self.assertEqual(soon[0]["priority"], 2)                           # 2026-12-31 is 70 days out
        self.assertEqual(self.run_collect({".php-version": "8.4.1"}, net)["alerts"], [])
        self.assertEqual(self.run_collect({".php-version": "9.9"}, net)["alerts"], [])   # unknown cycle: no guess

    def test_runtime_flaw_on_the_exploited_list_is_possibly_affected_not_affected(self):
        net = FakeNet(eol={"php": PHP_CYCLES}, kev=[
            {"cveID": "CVE-2026-0001", "vendorProject": "PHP Group", "product": "PHP", "vulnerabilityName": "PHP Remote Code Execution",
             "dateAdded": "2026-10-21", "requiredAction": "Apply updates."},
            {"cveID": "CVE-2020-0002", "vendorProject": "PHP Group", "product": "PHP", "dateAdded": "2020-01-01"},       # too old
            {"cveID": "CVE-2026-0003", "vendorProject": "Acme", "product": "Widget", "dateAdded": "2026-10-21"}])          # not ours
        alerts = self.run_collect({".php-version": "8.4.1"}, net)["alerts"]
        kev = [a for a in alerts if a["kind"] == "runtime-exploited"]
        self.assertEqual([a["ids"] for a in kev], [["CVE-2026-0001"]])
        self.assertEqual(kev[0]["priority"], 0)
        self.assertIn("POSSIBLY AFFECTED", kev[0]["action"])
        self.assertNotIn("you are affected", kev[0]["action"].lower())
        self.assertTrue(kev[0]["url"].startswith("https://nvd.nist.gov/"))

    def test_nothing_runtime_related_means_no_runtime_alert(self):
        net = FakeNet(kev=[{"cveID": "CVE-2026-0001", "vendorProject": "PHP Group", "product": "PHP", "dateAdded": "2026-10-21"}])
        self.assertEqual(self.run_collect({"package.json": {"name": "x"}}, net)["alerts"], [])   # a Node app is not told about PHP

    def test_feed_down_is_never_reported_as_all_clear(self):
        net = FakeNet(down=("osv", "kev", "eol"))
        r = self.run_collect({"package-lock.json": LOCK, ".php-version": "7.4"}, net)
        self.assertEqual(r["alerts"], [])
        self.assertEqual(r["coverage"]["feeds"]["osv"], "unreachable")
        self.assertEqual(r["coverage"]["packages_checked"], 0)             # not 2: nothing was actually checked
        text = adv.render_text(r)
        self.assertIn("INCOMPLETE", text)
        self.assertIn("not an all-clear", text)
        self.assertIn("cannot tell you that you are safe", text)

    def test_unpinned_packages_are_reported_not_guessed(self):
        net = FakeNet()
        r = self.run_collect({"package.json": {"dependencies": {"left-pad": "^1"}}}, net)
        self.assertEqual(r["coverage"]["packages_unpinned_not_checked"], 1)
        self.assertIn("not checked", adv.render_text(r))
        self.assertFalse([c for c in net.calls if c.startswith(adv.OSV_BATCH)])   # no version, so no query

    def test_only_names_and_versions_are_sent_to_osv(self):
        sent = []
        net = FakeNet()
        orig = net.__call__

        def spy(method, url, body=None, timeout=15.0):
            if body:
                sent.append(json.dumps(body))
            return orig(method, url, body, timeout)
        adv.collect(project({"package-lock.json": LOCK, "server.js": "const SECRET = 'do-not-send';"}), adv.Feeds(spy), TODAY)
        self.assertTrue(sent)
        self.assertNotIn("do-not-send", "".join(sent))
        self.assertTrue(all(set(q["package"]) == {"name", "ecosystem"} for s in sent for q in json.loads(s)["queries"]))


class StateAndRendering(unittest.TestCase):
    def result(self):
        net = FakeNet(osv={("lodash", "4.17.15"): ["GHSA-p6mc-m468-83gw"]}, vulns={"GHSA-p6mc-m468-83gw": LODASH_VULN})
        return adv.collect(project({"package-lock.json": LOCK}), adv.Feeds(net), TODAY)

    def test_new_vs_seen(self):
        r = adv.mark_new(self.result(), {})
        self.assertTrue(r["alerts"][0]["new"])
        r = adv.mark_new(self.result(), {"seen": [r["alerts"][0]["key"]]})
        self.assertFalse(r["alerts"][0]["new"])
        self.assertIn("No new advisories", adv.render_text(r, only_new=True))

    def test_markdown_has_marker_links_and_footer(self):
        md = adv.render_markdown(adv.mark_new(self.result(), {}))
        self.assertTrue(md.startswith("<!-- ai-consultant-advisories -->"))
        self.assertIn("https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw", md)
        self.assertIn("cannot tell you that you are safe", md)


class Hook(unittest.TestCase):
    def setup(self, enabled=True):
        files = {"package-lock.json": LOCK}
        if enabled:
            files[".consultant/alerts.json"] = {"enabled": True}
        return project(files)

    def net(self, **kw):
        return FakeNet(osv={("lodash", "4.17.15"): ["GHSA-p6mc-m468-83gw"]}, vulns={"GHSA-p6mc-m468-83gw": LODASH_VULN}, **kw)

    def test_silent_unless_the_project_opted_in(self):
        net = self.net()
        self.assertIsNone(adv.run_hook(self.setup(enabled=False), net, today=TODAY))
        self.assertEqual(net.calls, [])                                    # no network without consent

    def test_reminds_once_then_stays_quiet(self):
        root, net = self.setup(), self.net()
        msg = adv.run_hook(root, net, now=1000.0, today=TODAY)
        self.assertIn("1 new security advisory affects this project", msg)
        self.assertIn("/ai-consultant:consult-alerts", msg)
        self.assertIsNone(adv.run_hook(root, net, now=2000.0, today=TODAY))   # already told

    def test_cache_avoids_refetching_within_a_day_and_expires_after(self):
        root, net = self.setup(), self.net()
        adv.run_hook(root, net, now=0.0, today=TODAY)
        calls = len(net.calls)
        adv.run_hook(root, net, now=3600.0, today=TODAY)
        self.assertEqual(len(net.calls), calls)
        adv.run_hook(root, net, now=26 * 3600.0, today=TODAY)
        self.assertGreater(len(net.calls), calls)

    def test_outage_is_not_cached_and_never_raises(self):
        root = self.setup()
        self.assertIsNone(adv.run_hook(root, self.net(down=("osv", "kev", "eol")), now=0.0, today=TODAY))
        self.assertFalse((root / ".consultant" / "cache" / "advisories.json").exists())   # an outage must not hide alerts for a day

        def boom(*a, **k):
            raise RuntimeError("network exploded")
        self.assertIsNone(adv.run_hook(self.setup(), boom, now=0.0, today=TODAY))

    def test_time_budget_stops_slow_feeds(self):
        feeds = adv.Feeds(lambda *a, **k: (200, {"vulnerabilities": []}), budget=0.0001)
        import time
        time.sleep(0.01)
        self.assertEqual(feeds.kev(), None)                                # budget spent: no call made, reported unreachable
        self.assertEqual(feeds.status["kev"], "unreachable")


class Cli(unittest.TestCase):
    def run_cli(self, root, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "advisories.py"), "--root", str(root), "--offline", *args],
                              capture_output=True, text=True)

    def test_offline_json_is_valid_and_honest(self):
        r = self.run_cli(project({"package-lock.json": LOCK}), "--format", "json")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["coverage"]["feeds"]["osv"], "unreachable")

    def test_hook_mode_prints_nothing_when_not_opted_in(self):
        r = self.run_cli(project({"package-lock.json": LOCK}), "--hook")
        self.assertEqual((r.returncode, r.stdout), (0, ""))

    def test_mark_seen_writes_state(self):
        root = project({"package-lock.json": LOCK})
        self.assertEqual(self.run_cli(root, "--mark-seen").returncode, 0)
        self.assertTrue((root / ".consultant" / "alerts-state.json").exists())


if __name__ == "__main__":
    unittest.main()
