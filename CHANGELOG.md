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

Not yet done: the workflow templates have not been run on GitHub Actions; scanner output parsing is tested only against fixture JSON, not real tool output.
