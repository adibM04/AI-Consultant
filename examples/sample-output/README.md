# Sample output

Illustrative only. `findings/*.json` were written by hand against `examples/vibe-coded-app/server.js`
to show the data format and what the rendered `REPORT.md` looks like. They are not the output of a
live audit, and only five domains are filled in, so most items show as "not audited".

Regenerate the report with:

    python3 scripts/render_report.py --dir examples/sample-output --today 2026-10-15
