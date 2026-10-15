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

## Improve the auditors

`agents/domain-auditor.md` and `skills/*/SKILL.md` are prompts. If the consultant gave a wrong result, open a "Wrong audit result" issue with a minimal repro, or better, extend `examples/vibe-coded-app/` and `expected-findings.json` so the case is covered.

## Change the verdict

The verdict logic is in `scripts/render_report.py` and has tests. A change that makes any verdict more lenient needs a stated reason in the PR.

## Ground rules

- Python scripts used at runtime stay standard-library only. PyYAML is allowed only for checklist authoring (`scripts/checklist.py`).
- Nothing in this repo may phone home or send audited code anywhere.
- No real secrets in fixtures, even expired ones.
