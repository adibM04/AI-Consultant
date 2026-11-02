# Contributing

The most valuable contributions are things only someone who has been paged at 3am would know.

## Set up

```bash
python3 scripts/dev.py check    # macOS / Linux
python  scripts/dev.py check    # Windows
```

That is everything CI runs: checklist schema, a fresh `checklist.json`, the unit tests,
a sample report and the plugin manifests. It needs Python 3.11+ and nothing else;
`pip install pyyaml` is only needed to edit the checklist. The map of the repository is
in [docs/development.md](docs/development.md).

## Add or change a checklist item

1. Edit the right file in `checklist/`. Every item needs:

   | field | meaning |
   |---|---|
   | `id` | `ABC-01` style, unique, stable forever |
   | `title` | the control, phrased so that "yes/no" is answerable |
   | `severity` | `critical` (customers or money exposed now), `high`, `medium`, `low` |
   | `tier` | `1` before the first paying customer, `2` before scaling, `3` enterprise/regulated |
   | `when` | tags that make it apply, `[]` for always. Tags are listed in `scripts/checklist.py` |
   | `evidence` | `code` (visible in source), `config` (visible in IaC/CI/config if present), `process` (needs a human) |
   | `role` | who normally owns it |
   | `check` | how an auditor verifies it, and the common failure patterns to look for |

2. `python3 scripts/checklist.py validate` then `python3 scripts/checklist.py build`. Commit the regenerated `checklist/checklist.json`.
3. `python3 scripts/dev.py check`

Rules of thumb: be honest about `evidence`. If an auditor cannot see it from a repository, mark it `process`, so it reports `unknown` instead of guessing. Keep severity `critical` for things that expose customers or money, not for good hygiene. Do not renumber ids.

## Add a stack playbook

1. Write `stacks/<id>.md`. Start with a one-paragraph "why this stack fails", then a top-level `Maps to:` line, then checks as `## XX-1 Title` sections. Each check needs its own `Maps to:` line (checklist ids), what to look for, when it fails, and the fix. Say `unknown` plus a question when the repo cannot settle it (dashboard settings, plan tiers), and say what is public by design so auditors do not raise false alarms (Supabase anon key, Firebase web config).
2. Register it in `stacks/stacks.json` with detection rules (dependency names, file paths, content patterns).
3. `python3 scripts/dev.py check` checks that the playbook is registered and every `Maps to:` id exists.
4. Prefer adding a case to a fixture in `examples/` and its `expected-findings.json` so the playbook has something to be tested against. Fixture package names must be invented or well-known typos, never a name you have not checked, and fixtures must say "do not install".

## Improve the auditors

`agents/domain-auditor.md` and `skills/*/SKILL.md` are prompts. If the consultant gave a wrong result, open a "Wrong audit result" issue with a minimal repro, or better, extend `examples/vibe-coded-app/` and `expected-findings.json` so the case is covered.

## Change attestations or the questionnaire tool

Both exist to stop the tool from helping someone overclaim, so keep their invariants and their tests: attestations never apply to code-checkable items, never override a `fail`/`partial`, require an existing evidence file and expire within a year; questionnaire stances are capped by item states, prose is discarded when overruled, and "not assessed" never becomes "not applicable". New keyword themes go in `checklist/questionnaire-topics.json` (a test checks every item id exists).

## Change the PR guard or the Action

`scripts/pr_guard.py` is tested against real temporary git repositories (`tests/test_pr_guard.py`). Keep two properties: the baseline is read from the base ref only, and nothing from the pull request is executed, and secret-file contents are never read or printed. Inputs reach `action.yml`'s shell only through `env:`, never by `${{ }}` interpolation (a test enforces this). `templates/weekly-audit.yml` must stay schedule/manual only.

## Cut a release

1. Update `CHANGELOG.md`, bump `version` in `.claude-plugin/plugin.json`.
2. Update the pinned `@vX.Y.Z` / `ref: vX.Y.Z` in `docs/ci.md` and `templates/` to the new version (a test fails if they disagree with `plugin.json`).
3. Run `python3 scripts/dev.py check`, commit and push the branch. Tag that commit (`git tag -a vX.Y.Z -m "..."`) and push the tag. If tag pushes are blocked where you work, pin the docs and templates to the full commit SHA with a `# vX.Y.Z` comment instead (the drift test accepts both) and create the tag from a machine that can.

## Run the evals

`python3 evals/run_eval.py <fixture> --yes` runs the real consultant on a fixture and scores it. See `evals/README.md`: it uses a model with shell access on hostile input, costs money, and belongs in a disposable environment. Run it after changing a skill or the auditor prompt, and say in the PR what it showed.

## Change the verdict

The verdict logic is in `scripts/render_report.py` and has tests. A change that makes any verdict more lenient needs a stated reason in the PR.

## A good first contribution

You do not have to understand the whole pipeline to help. Start with the
[good first issue](https://github.com/adibM04/AI-Consultant/labels/good%20first%20issue)
label: each one is self-contained and says how to check your work. The
[roadmap](ROADMAP.md) shows what is next and what the project will not do.

These are the kinds of changes that get merged fastest:

- **A missing check.** A production failure you have seen that no item covers. Use the
  "Propose a checklist item" issue; the bar is a real incident, not a best practice.
- **A wrong finding.** The auditor failed something that is fine, or passed something
  that is broken. A minimal repo plus the check id is enough for a fix.
- **A stack playbook for what you actually deploy.** Vercel, Fly.io, Railway, Clerk,
  Drizzle, Prisma, RLS policies: the playbook pattern is one Markdown file and a registry
  entry. `stacks/nextjs.md` is the shortest example.
- **A fixture.** An app shape the current examples do not cover, with the findings you
  expect. Fixtures must use invented package names and say "do not install".
- **A word that is wrong.** The docs aim to be honest, and a sentence that overclaims is
  a bug.

Small PRs are easier to review than large ones, and a test that reproduces the problem
is worth more than a paragraph describing it. If you are unsure where to start, open an
[Ideas discussion](https://github.com/adibM04/AI-Consultant/discussions/categories/ideas)
or comment on the roadmap issue.

## Ground rules

- Python scripts used at runtime stay standard-library only. Scripts that look at a project must never execute, install or import anything from it. PyYAML is allowed only for checklist authoring (`scripts/checklist.py`).
- Nothing in this repo may phone home or send audited code anywhere.
- No real secrets in fixtures, even expired ones.
