# Contributing

The most valuable contributions are things only someone who has been paged at 3am would know.

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
3. `python3 -m unittest discover -s tests`

Rules of thumb: be honest about `evidence`. If an auditor cannot see it from a repository, mark it `process`, so it reports `unknown` instead of guessing. Keep severity `critical` for things that expose customers or money, not for good hygiene. Do not renumber ids.

## Add a stack playbook

1. Write `stacks/<id>.md`. Start with a one-paragraph "why this stack fails", then a top-level `Maps to:` line, then checks as `## XX-1 Title` sections. Each check needs its own `Maps to:` line (checklist ids), what to look for, when it fails, and the fix. Say `unknown` plus a question when the repo cannot settle it (dashboard settings, plan tiers), and say what is public by design so auditors do not raise false alarms (Supabase anon key, Firebase web config).
2. Register it in `stacks/stacks.json` with detection rules (dependency names, file paths, content patterns).
3. `python3 -m unittest discover -s tests` checks that the playbook is registered and every `Maps to:` id exists.
4. Prefer adding a case to a fixture in `examples/` and its `expected-findings.json` so the playbook has something to be tested against. Fixture package names must be invented or well-known typos, never a name you have not checked, and fixtures must say "do not install".

## Improve the auditors

`agents/domain-auditor.md` and `skills/*/SKILL.md` are prompts. If the consultant gave a wrong result, open a "Wrong audit result" issue with a minimal repro, or better, extend `examples/vibe-coded-app/` and `expected-findings.json` so the case is covered.

## Change the PR guard or the Action

`scripts/pr_guard.py` is tested against real temporary git repositories (`tests/test_pr_guard.py`). Keep two properties: the baseline is read from the base ref only, and nothing from the pull request is executed, and secret-file contents are never read or printed. Inputs reach `action.yml`'s shell only through `env:`, never by `${{ }}` interpolation (a test enforces this). `templates/weekly-audit.yml` must stay schedule/manual only.

## Run the evals

`python3 evals/run_eval.py <fixture> --yes` runs the real consultant on a fixture and scores it. See `evals/README.md`: it uses a model with shell access on hostile input, costs money, and belongs in a disposable environment. Run it after changing a skill or the auditor prompt, and say in the PR what it showed.

## Change the verdict

The verdict logic is in `scripts/render_report.py` and has tests. A change that makes any verdict more lenient needs a stated reason in the PR.

## Ground rules

- Python scripts used at runtime stay standard-library only. Scripts that look at a project must never execute, install or import anything from it. PyYAML is allowed only for checklist authoring (`scripts/checklist.py`).
- Nothing in this repo may phone home or send audited code anywhere.
- No real secrets in fixtures, even expired ones.
