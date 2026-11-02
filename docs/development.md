# Working on the repository

This is the contributor path. If you only want to *use* the consultant, the
[README](../README.md) is shorter. If you want to add a checklist item, a stack
playbook, or a better auditor prompt, this page tells you where things live and how to
check your work.

## Requirements

- Python 3.11 or newer (the scripts use `tomllib` and `X | None` annotations).
- PyYAML, only for editing the checklist and for the tests that build it.
- Git, for the PR-guard tests (they create real temporary repositories).
- Nothing else. No Node, no database, no API key.

You do **not** need a Claude Code install or an API key to run the test suite. Only the
[evals](../evals/README.md) call a model, and those cost money.

## One command

```bash
python3 scripts/dev.py check    # macOS and Linux
python  scripts/dev.py check    # Windows (or: py scripts/dev.py check)
```

That runs exactly what CI runs: checklist schema, the generated JSON check, all unit
tests, a sample report render, and the plugin manifests.

```bash
python3 scripts/dev.py build    # after editing checklist/*.yml, regenerate checklist/checklist.json
```

`dev.py` runs its children with `PYTHONUTF8=1`, so a Windows console code page cannot
change the result. If you prefer the raw commands, they are the same ones in
`.github/workflows/ci.yml`.

## First 30 minutes

1. `git clone https://github.com/adibM04/AI-Consultant && cd AI-Consultant`
2. `python3 scripts/dev.py check` (Windows: `python scripts/dev.py check`) — the full
   suite, no network, a few seconds.
3. Try the tool on the deliberately broken app:

   ```bash
   cd examples/vibe-coded-app
   claude
   > /ai-consultant:consult
   ```

   Pick `launch`, say yes to payments. You should get `NOT READY` with the SQL
   injection, the unauthenticated invoices, the MD5 passwords and the hard-coded key.
   Delete the generated `.consultant/` folder afterwards.
4. Pick something from the [good first issues](https://github.com/adibM04/AI-Consultant/labels/good%20first%20issue),
   or read "Where to change what" below.

## Where to change what

| You want to change | Edit | Then |
|---|---|---|
| What the audit checks | `checklist/*.yml` | `python3 scripts/dev.py build`, commit `checklist/checklist.json` |
| How a stack is audited | `stacks/<id>.md` and `stacks/stacks.json` | `python3 scripts/dev.py check` |
| What the auditor does | `agents/domain-auditor.md`, `skills/*/SKILL.md` | run the matching eval if you can |
| The verdict rules | `scripts/render_report.py` | tests in `tests/test_render_report.py`; say why in the PR |
| The PR guard | `scripts/pr_guard.py`, `action.yml` | `tests/test_pr_guard.py` |
| The sample report | `examples/sample-output/` | `python3 scripts/render_report.py --dir examples/sample-output --today 2026-10-15` |

The long version of each rule is in [CONTRIBUTING.md](../CONTRIBUTING.md); this is the
map, not a replacement.

## The moving parts

```
checklist/        YAML source of truth, plus generated checklist.json (never hand-edit it)
scripts/          standard-library-only tools run by the skills and CI
  dev.py          the one-command local check
  render_report.py the verdict, computed by fixed rules
  questionnaire.py, attest.py, advisories.py, pr_guard.py
skills/           one prompt per slash command; they call the scripts above
agents/           domain-auditor.md, the prompt that reads a domain
stacks/           per-framework playbooks (Supabase, Firebase, Next.js, Stripe)
examples/         fixtures to test against, and one unedited real run
evals/            the harness that runs the real model on fixtures (costs money)
templates/        ready-made workflows for a founder's own repository
tests/            unittest; `python3 -m unittest discover -s tests`
```

Two invariants matter more than the rest:

- **Item ids are stable.** Never renumber or reuse one. To retire an item, change its
  text and mark it obsolete, so saved waivers and audit history stay meaningful.
- **A check must be honest about its evidence.** If a repository cannot show it, it is
  `process`, not `code`. An auditor that guesses is worse than one that says `unknown`.

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `build --check` fails | `checklist/*.yml` changed but `checklist.json` was not rebuilt | `python3 scripts/dev.py build` and commit it |
| Tests skip | PyYAML is not installed | `pip install pyyaml`; CI always installs it |
| `python3` not found on Windows | Windows ships `python` / `py` | use `python` (or `py`), or WSL |
| The action test skips on Windows | it runs the composite action's `bash` script | expected; Linux and macOS cover it |
| An eval wants money | evals run a real model with shell access | read [evals/README.md](../evals/README.md) first |

## Before you open the pull request

- `python3 scripts/dev.py check` is green.
- If you touched the checklist, `checklist/checklist.json` is committed.
- If you touched a skill or the auditor prompt, say what the eval showed, or why you
  did not run it.
- No real secrets, customer data, or personal data in fixtures, tests, or screenshots.
- The PR template has a short checklist; fill it in rather than deleting it.
