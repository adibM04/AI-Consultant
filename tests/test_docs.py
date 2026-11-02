import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "docs" / "assets"))

import make_demo_gif as demo  # noqa: E402

DOCS = sorted(
    {p for p in [
        ROOT / "README.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CHANGELOG.md",
        ROOT / "ROADMAP.md",
        ROOT / "SUPPORT.md",
        ROOT / ".github" / "CODE_OF_CONDUCT.md",
        ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
        ROOT / "evals" / "README.md",
        *(ROOT / "docs").glob("*.md"),
        *(ROOT / "examples").glob("*/README.md"),
        *(ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.md"),
    ] if p.exists()},
    key=str,
)
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)|<img[^>]+src=\"([^\"]+)\"")


class Links(unittest.TestCase):
    def test_every_relative_link_and_image_resolves(self):
        broken = []
        for doc in DOCS:
            for m in LINK.finditer(doc.read_text(encoding="utf-8")):
                target = m.group(1) or m.group(2)
                if re.match(r"^(https?:|mailto:|#)", target):
                    continue
                path = (doc.parent / target.split("#")[0]).resolve()
                if not path.exists():
                    broken.append(f"{doc.relative_to(ROOT)} -> {target}")
        self.assertEqual(broken, [])

    def test_readme_is_a_landing_page_not_a_manual(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertLess(len(text), 7000, "move detail into docs/")
        first_screen = text[: text.index("## Install")]
        self.assertIn("docs/assets/demo.gif", first_screen)          # the demo is above the fold
        self.assertIn("workflows/ci.yml/badge.svg", first_screen)
        self.assertNotIn("stars", first_screen.lower())               # no invented social proof

    def test_every_doc_is_linked_from_the_readme(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for doc in (ROOT / "docs").glob("*.md"):
            self.assertIn(f"docs/{doc.name}", readme, f"{doc.name} is orphaned")


class Counts(unittest.TestCase):
    """The count is written by hand in several places, so guard it against the checklist."""

    def test_documented_counts_match_the_checklist(self):
        data = json.loads((ROOT / "checklist" / "checklist.json").read_text(encoding="utf-8"))
        items = sum(len(d["items"]) for d in data["domains"])
        domains = len(data["domains"])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertTrue(f"{items} production checks" in readme,
                        f"README.md: expected '{items} production checks'")
        self.assertTrue(f"checks-{items}" in readme,
                        f"README.md: expected the badge to say checks-{items}")
        page = (ROOT / "docs" / "checklist.md").read_text(encoding="utf-8")
        self.assertTrue(f"{items} items in {domains} domains" in page,
                        f"docs/checklist.md: expected '{items} items in {domains} domains'")
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertTrue(f"{items}-item" in plugin["description"],
                        f".claude-plugin/plugin.json: expected a {items}-item description")
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        self.assertTrue(f"{items} checks" in market["plugins"][0]["description"],
                        f".claude-plugin/marketplace.json: expected '{items} checks'")


class DemoGif(unittest.TestCase):
    def test_numbers_come_from_the_real_run(self):
        data = demo.load_real_run()
        report = (ROOT / "examples" / "real-run" / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn(f"| {data['pass']} | {data['fail']} | {data['partial']} | {data['unknown']} |", report)
        self.assertEqual(data["refs"]["AUT-02"], "server.js:34-37")
        self.assertEqual(data["refs"]["SEC-06"], "server.js:16,23,30,35")
        self.assertEqual(data["roles"][0][0], "Security engineer")

    def test_committed_gif_is_a_real_animation_of_sane_size(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed")
        path = ROOT / "docs" / "assets" / "demo.gif"
        self.assertLess(path.stat().st_size, 1_000_000)               # loads fast on a README
        with Image.open(path) as im:
            self.assertGreaterEqual(im.n_frames, 20)
            self.assertEqual(im.info.get("loop"), 0)                  # loops

    def test_generator_fails_loudly_when_the_real_run_no_longer_matches(self):
        import json, shutil, tempfile
        tmp = Path(tempfile.mkdtemp()) / "real"
        shutil.copytree(ROOT / "examples" / "real-run", tmp)
        f = tmp / "findings" / "authorization.json"
        d = json.loads(f.read_text(encoding="utf-8"))
        for item in d["items"]:
            if item["id"] == "AUT-02":
                item["status"] = "pass"
        f.write_text(json.dumps(d), encoding="utf-8")
        with self.assertRaises(SystemExit):
            demo.load_real_run(tmp)


if __name__ == "__main__":
    unittest.main()
