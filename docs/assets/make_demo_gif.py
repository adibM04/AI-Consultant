#!/usr/bin/env python3
"""Draw the README demo GIF: a replay of a real run.

The counts, blocker file references and role counts are read from examples/real-run (the unedited
output of the real plugin), so the picture cannot drift from the report it shows. What is staged:
the typing of the command and the four progress lines, which are a replay of the skill's real steps.
Say so wherever the GIF is shown.

    python3 docs/assets/make_demo_gif.py [docs/assets/demo.gif]

Needs Pillow and a monospace TTF (DejaVu Sans Mono). Contributors only; users never run this.
"""
from __future__ import annotations

import glob
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
REAL = ROOT / "examples" / "real-run"

# Short, faithful labels for the blockers shown in the GIF. The findings' own text is longer.
BLOCKERS = [
    ("AUT-02", "Any caller can read any invoice by changing the id"),
    ("SEC-06", "SQL injection: login bypass and data theft"),
    ("IDN-03", "Passwords hashed with unsalted MD5"),
    ("IDN-06", "No rate limiting on signup, login or reset"),
    ("SEC-01", "Stripe-style secret key hard-coded in source"),
]
UNKNOWN_ID, UNKNOWN_TEXT = "DAT-08", "No restore runbook or drill record. Show a tested restore."


def load_real_run(real: Path = REAL) -> dict:
    """Pull everything the GIF displays out of the real run's report and findings."""
    report = (real / "REPORT.md").read_text(encoding="utf-8")
    row = re.search(r"^\| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|$", report, re.M)
    if not row:
        raise SystemExit("could not find the summary table in examples/real-run/REPORT.md")
    passed, failed, partial, unknown = (int(row.group(i)) for i in range(1, 5))

    findings = {}
    for f in sorted(glob.glob(str(real / "findings" / "*.json"))):
        for item in json.loads(Path(f).read_text(encoding="utf-8"))["items"]:
            findings[item["id"]] = item

    def ref(item_id: str) -> str:
        """First file in the evidence, with every line number cited for it: server.js:16,23,30,35."""
        refs = [e for e in findings[item_id].get("evidence", []) if re.match(r"^[\w./-]+:\d", e)]
        if not refs:
            return ""
        file = refs[0].split(":")[0]
        lines = [e.split(":", 1)[1] for e in refs if e.split(":")[0] == file]
        return f"{file}:{','.join(lines)}" if len(lines) > 1 and all("-" not in x for x in lines) else f"{file}:{lines[0]}"

    for item_id, _ in BLOCKERS:
        if findings[item_id]["status"] != "fail":
            raise SystemExit(f"{item_id} is no longer a failing finding in examples/real-run; update BLOCKERS")
    if findings[UNKNOWN_ID]["status"] != "unknown":
        raise SystemExit(f"{UNKNOWN_ID} is no longer unknown in examples/real-run; update UNKNOWN_ID")

    roles = re.findall(r"^\| ([A-Za-z ]+?) \| (\d+) \| (\d+) \| ", report.split("People this product still needs")[1], re.M)
    top = [(name.replace(" engineer", "") if name == "DevOps engineer" else name, int(n)) for name, n, _ in roles[:3]]
    project = re.search(r"^# Production readiness report: (.+)$", report, re.M).group(1)
    return {"pass": passed, "fail": failed, "partial": partial, "unknown": unknown, "project": project,
            "refs": {i: ref(i) for i, _ in BLOCKERS}, "roles": top}


def build(out: Path, data: dict) -> tuple[int, float]:
    from PIL import Image, ImageDraw, ImageFont

    W, H, PAD, LH = 880, 540, 26, 25
    mono = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    bold = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
    FONT, BOLD, SMALL = (ImageFont.truetype(mono, 16), ImageFont.truetype(bold, 16), ImageFont.truetype(mono, 13))
    CW = FONT.getlength("M")
    BG, BAR = (13, 17, 23), (22, 27, 34)
    WHITE, GRAY = (230, 237, 243), (139, 148, 158)
    RED, YEL, GRN, CYA = (255, 123, 114), (227, 179, 65), (63, 185, 80), (121, 192, 255)

    def frame(lines, cursor=None):
        im = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(im)
        d.rectangle([0, 0, W, 38], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([18 + i * 22, 13, 30 + i * 22, 25], fill=c)
        d.text((W // 2, 19), "my-startup  ~  claude", font=SMALL, fill=GRAY, anchor="mm")
        y = 38 + PAD
        for segs in lines:
            x = PAD
            for text, color, *b in segs:
                d.text((x, y), text, font=BOLD if b and b[0] else FONT, fill=color)
                x += CW * len(text)
            y += LH
        if cursor is not None:
            cx, cy = cursor
            d.rectangle([PAD + CW * cx, 38 + PAD + LH * cy + 2, PAD + CW * cx + CW - 1, 38 + PAD + LH * cy + LH - 3], fill=WHITE)
        return im

    pad = lambda t, n: t + " " * max(0, n - len(t))
    frames, durs = [], []

    def add(lines, ms, cursor=None):
        frames.append(frame(lines, cursor))
        durs.append(ms)

    cmd = "/ai-consultant:consult"
    prompt = lambda typed: [("❯ ", CYA, True), (typed, WHITE)]
    add([prompt("")], 700, cursor=(2, 0))
    for n in range(2, len(cmd) + 1, 2):
        add([prompt(cmd[:n])], 70, cursor=(2 + n, 0))
    add([prompt(cmd)], 500, cursor=(2 + len(cmd), 0))

    steps = [
        [("● ", GRN), ("Detected stack ", WHITE), ("Node.js · Express · Stripe", GRAY)],
        [("● ", GRN), ("Profile ", WHITE), ("stage: launch · tags: b2b, payments", GRAY)],
        [("● ", GRN), ("Fact checks ", WHITE), ("packages exist? · secrets · stack playbooks", GRAY)],
        [("● ", GRN), ("Auditing 5 domains in parallel ", WHITE), ("identity · authorization · security · data · payments", GRAY)],
    ]
    shown = [prompt(cmd), []]
    for s in steps:
        shown.append(s)
        add(shown, 520)
    for dots in ("", ".", "..", "..."):
        add(shown[:-1] + [shown[-1] + [(dots, GRAY)]], 260)
    add(shown + [[], [("✓ ", GRN, True), ("Report written to .consultant/REPORT.md", WHITE)]], 1100)

    R: list = []

    def show(line, ms):
        R.append(line)
        add(R, ms)

    show([("Production readiness: ", WHITE), (data["project"], GRAY)], 400)
    show([], 100)
    show([("Verdict  ", GRAY), ("NOT READY", RED, True)], 900)
    show([("         ", GRAY), (f"{data['pass']} pass", GRN), (" · ", GRAY), (f"{data['fail']} fail", RED), (" · ", GRAY),
          (f"{data['partial']} partial", YEL), (" · ", GRAY), (f"{data['unknown']} could not be verified", YEL)], 900)
    show([], 100)
    show([("BLOCKERS", GRAY, True)], 400)
    for item_id, text in BLOCKERS:
        show([("✗ ", RED, True), (item_id + "  ", CYA), (pad(text, 52), WHITE), (data["refs"][item_id], GRAY)], 700)
    show([], 100)
    show([("NEEDS YOU", GRAY, True)], 400)
    show([("? ", YEL, True), (UNKNOWN_ID + "  ", CYA), (pad(UNKNOWN_TEXT, 52), WHITE)], 900)
    show([], 100)
    show([("PEOPLE THIS STILL NEEDS", GRAY, True)], 400)
    roles = []
    for i, (name, n) in enumerate(data["roles"]):
        roles += [(("  " if i == 0 else "   ") + name + " ", WHITE), (str(n), RED)]
    show(roles, 3800)

    out.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durs, loop=0, optimize=True, disposal=1)
    return len(frames), sum(durs) / 1000


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "assets" / "demo.gif"
    data = load_real_run()
    n, secs = build(out, data)
    print(f"wrote {out} ({n} frames, {secs:.1f}s) from examples/real-run: "
          f"{data['pass']} pass, {data['fail']} fail, {data['partial']} partial, {data['unknown']} unknown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
