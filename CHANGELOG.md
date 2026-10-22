# Changelog

## 0.2.0

- **Advisory watch** (`/ai-consultant:consult-alerts`, `scripts/advisories.py`): checks your exact lockfile and pinned versions against OSV, CISA's known-exploited list and endoflife.date, and says what to upgrade first. Facts come only from feeds. Unpinned packages are reported as not checked, runtime flaws as "possibly affected", an unreachable feed as incomplete, and it never says you are safe. See `docs/alerts.md`.
- Opt-in `SessionStart` reminder in the terminal (`hooks/hooks.json`), and `templates/advisory-watch.yml` which keeps one GitHub issue up to date and comments only on new advisories, so GitHub emails watchers without any secret.
- `feeds-smoke` workflow: checks the real OSV, CISA and endoflife.date APIs weekly, so a changed API shows up as a red run. Its first live run found that upgrade advice pointed at older versions (OSV lists one fix per release branch); fixed, with a live assertion against it.
- **Verified:** the feeds, live on GitHub Actions. The hook, in a real headless Claude Code session (at the event level; how the message looks on screen was not seen). **Not yet verified:** the GitHub issue and email path against a real repository (unit tests with a fake GitHub API only).
- The items below, under the former "Unreleased" heading, ship in this version too.


- README rewritten as a short landing page: hook, demo GIF, install, commands, why the verdict can be trusted. The detail moved to `docs/` (checklist, how it works, evidence and questionnaires, CI, limits), with nothing removed.
- `docs/assets/demo.gif`: a replay of a real run. Counts, file references and role counts are read from `examples/real-run` by `docs/assets/make_demo_gif.py`; only the typed command and the progress lines are staged.
- Tests that every relative link and image in the docs resolves, that the README stays short with the demo above the fold, and that the GIF matches the real run.

## 0.1.1

Fixes found by running the PR guard on real GitHub Actions and the scanner wrappers against real tools. **Upgrade the pinned action SHA**: 0.1.0 aborted before posting the job summary and the PR comment whenever it found something blocking.

- PR guard action: no longer aborts under `bash -e` before the summary and comment; prints the report in the job log; PR-controlled text cannot form workflow commands; help text no longer loses its formatting.
- Scanner wrappers: gitleaks findings distinguish a secret still in the working tree from one only in git history; semgrep mapping ignores a rule file's directory prefix; silent tool failures report an exit code and a hint.
- `templates/weekly-audit.yml`: the plugin is moved out of the audited workspace before the audit, manual runs can limit domains and set a hard budget, inputs are validated, the file warns about using a dedicated low-limit API key, and a missing key now fails with a plain message while a failed run shows the end of Claude's output.
- **Weekly audit workflow, partly verified on a real runner:** manual dispatch with inputs, both checkouts, moving the plugin out of the workspace, installing Claude Code, the committed-profile check, input validation, and the new API-key preflight message all ran as intended. **The model run itself, the report summary, the artifact upload and the final `--ci` step have not run**, because the test repository has no `ANTHROPIC_API_KEY` secret. Try it with a manual run limited to one or two domains and a small budget before relying on the schedule.
- Not tagged: tag pushes were blocked where this was developed, so pins use the commit SHA. Create `v0.1.1` on that commit from a machine that can.

## 0.1.0

First release.

- **Checklist**: 170 items in 14 domains, scoped by stage (`launch`, `growth`, `enterprise`) and product tags, each with a severity, an owner role and a note on whether code, config or a person can settle it.
- **Audit**: `consult`, `consult-audit`, `consult-roadmap`, `consult-ask` skills and the read-only `domain-auditor` agent. The verdict is computed by tested rules in `scripts/render_report.py`.
- **Deterministic facts**: package verifier (hallucinated names, typosquats), scanner wrapper (gitleaks, osv-scanner, trivy, semgrep), stack detection with Supabase, Firebase, Next.js, Stripe and AI-builder playbooks.
- **Hardening in code**: a `pass` must cite a real file and line; waivers need a person, a creation date and a short expiry; attestations apply only to items code cannot show; a failing code finding is never overridden.
- **Evidence loop**: `consult-evidence` and `scripts/attest.py` (refuses evidence that looks like secrets).
- **Questionnaires**: `consult-questionnaire` and `scripts/questionnaire.py`, with stances capped by the audit and overruled prose replaced by deterministic text.
- **CI**: `action.yml` PR guard (no model, no secrets) and workflow templates.
- **Evals**: fixtures including a deliberately hostile repository, a scorer, and a headless runner; two skill scenarios. Baselines are single runs on one model, see `evals/README.md`.

### Verification status (2026-10-16)

- **GitHub Actions:** the `ci` workflow runs the unit tests on a clean runner for every push. The PR guard composite action has run on a real runner, on a benign range, on a deliberately hostile branch, and on a real `pull_request` event (a throwaway draft PR, since closed): the job failed as intended and the sticky comment was posted by `github-actions[bot]`, and a re-run updated that same comment instead of adding another. **Not yet exercised:** a pull request from a fork (read-only token, so the comment step is expected to skip and fall back to the job summary).
- **Scanners:** the gitleaks and semgrep parsers were checked against output from the real tools (gitleaks built from source, semgrep from PyPI with a local rule file). `osv-scanner` and `trivy` could not be installed or reach their databases in the test environment, so their parsers are still checked only against hand-written JSON. Semgrep's registry rule packs were unreachable there, so only the failure path was seen for them.
- The real pull-request run found a bug the earlier runs hid: GitHub runs the step with `bash -e`, so a blocking exit code aborted the script before the job summary and the comment. Fixed, with a regression test that runs the step under the runner's exact flags and fails without the fix.
- Other fixes found by those runs: working-tree secrets were labelled as git-history ones; the sanitiser stripped our own help text; a rule file's directory could leak into the checklist mapping; silent tool failures reported only "failed".
