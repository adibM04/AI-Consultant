import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import verify_packages as vp  # noqa: E402

NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)


def project(files: dict) -> Path:
    tmp = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp


def fake_fetch(table):
    """table maps URL substring -> (status, json). First match wins; no match -> network failure."""
    def fetch(url, timeout=15.0):
        for needle, resp in table:
            if needle in url:
                return resp
        return 0, None
    return fetch


def npm_doc(created="2020-01-01T00:00:00Z", repo="git+https://github.com/a/b.git", deprecated=False):
    return {"time": {"created": created, "1.0.0": created, "modified": created}, "dist-tags": {"latest": "1.0.0"},
            "repository": {"url": repo} if repo else None,
            "versions": {"1.0.0": {"deprecated": "gone"} if deprecated else {}}}


class Parsing(unittest.TestCase):
    def test_package_json_and_requirements_and_pyproject(self):
        root = project({
            "package.json": json.dumps({"dependencies": {"express": "^4", "left": "github:a/b", "alias": "npm:real-name@^1"},
                                        "devDependencies": {"vite": "5"}}),
            "requirements.txt": "Flask_Cors==4.0  # comment\n-r other.txt\n-e git+https://x/y.git#egg=y\nrequests[security]>=2\n",
            "sub/pyproject.toml": '[project]\ndependencies = ["Pydantic>=2", "localpkg @ file:///tmp/x"]\n',
            "node_modules/ignored/package.json": json.dumps({"dependencies": {"nope": "1"}}),
        })
        got = {(p["ecosystem"], p["name"]): p for p in vp.collect(root)}
        self.assertIn(("npm", "express"), got)
        self.assertIn(("npm", "real-name"), got)
        self.assertTrue(got[("npm", "left")]["non_registry"])
        self.assertIn(("pypi", "flask-cors"), got)
        self.assertIn(("pypi", "requests"), got)
        self.assertIn(("pypi", "pydantic"), got)
        self.assertNotIn(("npm", "nope"), got)
        self.assertTrue(any(p["non_registry"] and p["ecosystem"] == "pypi" for p in got.values()))


class Typosquat(unittest.TestCase):
    def test_flags_near_misses_only(self):
        self.assertEqual(vp.typosquat_target("npm", "axois"), "axios")
        self.assertEqual(vp.typosquat_target("npm", "expresss"), "express")
        self.assertEqual(vp.typosquat_target("pypi", "reqeusts"), "requests")
        self.assertIsNone(vp.typosquat_target("npm", "express"))
        self.assertIsNone(vp.typosquat_target("npm", "lodash-es"))
        self.assertIsNone(vp.typosquat_target("npm", "pgs"))  # too short to judge
        self.assertIsNone(vp.typosquat_target("npm", "totally-unrelated-name"))

    def test_edit_distance_counts_swaps_as_one(self):
        self.assertEqual(vp.edit_distance("ab", "ba"), 1)
        self.assertEqual(vp.edit_distance("kitten", "sitting"), 3)


class Judgement(unittest.TestCase):
    def run_one(self, files, table, offline=False):
        return vp.run(project(files), offline=offline, fetch=fake_fetch(table), now=NOW)

    def flags(self, result, name):
        return {f["code"] for p in result["flagged"] if p["name"] == name for f in p["flags"]}

    def test_hallucinated_package_is_not_found(self):
        r = self.run_one({"package.json": json.dumps({"dependencies": {"made-up-helper-zz": "1"}})},
                         [("registry.npmjs.org/made-up-helper-zz", (404, None))])
        self.assertEqual(self.flags(r, "made-up-helper-zz"), {"NOT_FOUND"})
        self.assertEqual(r["flagged"][0]["risk"], "high")

    def test_network_failure_is_never_reported_as_not_found(self):
        r = self.run_one({"package.json": json.dumps({"dependencies": {"some-lib-qq": "1"}})}, [])
        self.assertEqual(self.flags(r, "some-lib-qq"), set())
        self.assertEqual(r["unreachable"], ["some-lib-qq"])

    def test_new_low_download_no_repo(self):
        files = {"package.json": json.dumps({"dependencies": {"fresh-lib-qq": "1"}})}
        table = [("registry.npmjs.org/fresh-lib-qq", (200, npm_doc(created="2026-10-10T00:00:00Z", repo=None))),
                 ("downloads/point/last-week/fresh-lib-qq", (200, {"downloads": 12}))]
        self.assertEqual(self.flags(self.run_one(files, table), "fresh-lib-qq"),
                         {"NEW_PACKAGE", "FEW_DOWNLOADS", "NO_REPOSITORY"})

    def test_unreachable_download_api_does_not_flag_few_downloads(self):
        files = {"package.json": json.dumps({"dependencies": {"fine-lib-qq": "1"}})}
        table = [("registry.npmjs.org/fine-lib-qq", (200, npm_doc(created="2025-06-01T00:00:00Z")))]
        r = self.run_one(files, table)
        self.assertEqual(r["flagged"], [])

    def test_typosquat_of_popular_with_unknown_downloads_is_high(self):
        files = {"package.json": json.dumps({"dependencies": {"axois": "1"}})}
        r = self.run_one(files, [("registry.npmjs.org/axois", (200, npm_doc()))])
        self.assertIn("TYPOSQUAT_SUSPECT", self.flags(r, "axois"))
        self.assertEqual(r["flagged"][0]["risk"], "high")

    def test_popular_packages_are_not_looked_up(self):
        files = {"package.json": json.dumps({"dependencies": {"express": "4"}})}
        r = self.run_one(files, [])  # any lookup would fail and show as unreachable
        self.assertEqual(r["unreachable"], [])
        self.assertEqual(r["packages"][0]["lookup"], "known-popular")

    def test_offline_makes_no_requests_but_still_catches_typosquats(self):
        def boom(*a, **k):
            raise AssertionError("network used in offline mode")
        files = {"package.json": json.dumps({"dependencies": {"axois": "1", "mystery-lib": "1"}})}
        r = vp.run(project(files), offline=True, fetch=boom, now=NOW)
        self.assertEqual(self.flags(r, "axois"), {"TYPOSQUAT_SUSPECT"})
        self.assertEqual(r["mode"], "offline")

    def test_invalid_names_are_not_queried(self):
        def boom(*a, **k):
            raise AssertionError("queried invalid name")
        files = {"package.json": json.dumps({"dependencies": {"Bad Name/../x": "1"}})}
        r = vp.run(project(files), fetch=boom, now=NOW)
        self.assertEqual(self.flags(r, "bad name/../x"), {"INVALID_NAME"})

    def test_pypi_lookup(self):
        files = {"requirements.txt": "ghost-pkg-qq\n"}
        r = self.run_one(files, [("pypi.org/pypi/ghost-pkg-qq/json", (404, None))])
        self.assertEqual(self.flags(r, "ghost-pkg-qq"), {"NOT_FOUND"})


if __name__ == "__main__":
    unittest.main()
