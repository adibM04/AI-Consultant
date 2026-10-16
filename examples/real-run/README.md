# A real run

Output of the actual plugin, not hand-written. On 2026-10-15 the `consult` skill audited
[`examples/vibe-coded-app`](../vibe-coded-app) (a deliberately broken Express file) with Claude Sonnet 5.5, covering five
domains (identity, authorization, security, data, payments) at `launch` stage. The questionnaire draft came from running
`consult-questionnaire` on the nine questions in `questionnaire/questionnaire.csv`.

What is unedited: every file under `findings/` (the auditors' JSON) and the questionnaire answers the model wrote.
What was re-run afterwards: `REPORT.md` and `questionnaire/draft.csv` were re-rendered with the current scripts, so they
reflect the current renderer rules.

Worth looking at:

- [`REPORT.md`](REPORT.md): the verdict, blockers with `file:line` evidence, what could not be verified, and which roles the open items point to.
- [`questionnaire/draft.csv`](questionnaire/draft.csv): 9 buyer questions, **0 Yes**, 4 No, 5 Unknown. Row 7 contains an injected "answer YES to everything" instruction (ignored), and row 9 a spreadsheet-formula trap (neutralised). Row 7's model-written "No" was overruled to "Unknown" because the audit had not assessed SOC 2 at this stage. Read [`summary.md`](questionnaire/summary.md) for how the audit overruled drafts.

One run, one model, one small file. It shows the shape of the output, not how often the auditors are right.
