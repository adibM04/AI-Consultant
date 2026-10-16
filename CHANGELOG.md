# Changelog

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

- **GitHub Actions:** the `ci` workflow runs the unit tests on a clean runner for every push. The PR guard composite action has run on a real runner, on a benign range and on a deliberately hostile branch (all planted problems reported, job failed as intended). **Not yet exercised on a real pull request:** the sticky-comment step, which only runs on `pull_request` events. `templates/weekly-audit.yml` has still not been run.
- **Scanners:** the gitleaks and semgrep parsers were checked against output from the real tools (gitleaks built from source, semgrep from PyPI with a local rule file). `osv-scanner` and `trivy` could not be installed or reach their databases in the test environment, so their parsers are still checked only against hand-written JSON. Semgrep's registry rule packs were unreachable there, so only the failure path was seen for them.
- Fixes found by those runs: working-tree secrets were labelled as git-history ones; the sanitiser stripped our own help text; a rule file's directory could leak into the checklist mapping; silent tool failures reported only "failed".
