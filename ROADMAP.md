# Roadmap

This is a direction, not a promise. There are no dates. The order is the commitment:
something moves down only when it is replaced by something more useful, and it moves to
"Shipped" only when it is in a release.

The [pinned roadmap issue](https://github.com/adibM04/AI-Consultant/issues/12) is the
place to comment. This file is the canonical version and is updated with each release.

## Shipped in 0.2

- 193 checks in 14 domains, scoped by stage and product traits
- Seven commands: full audit, targeted re-audit, roadmap, ask, advisory watch, evidence,
  questionnaire
- Advisory watch against OSV, CISA KEV and endoflife.date
- A deterministic PR-guard GitHub Action and a weekly-audit template
- Evidence attestations and buyer questionnaires that cannot overclaim
- An eval harness with hostile fixtures

## Now: make it easy to contribute

The constraint is contributor time, not ideas. These are ready to pick up, and each says
exactly how to check your work:

- [#3](https://github.com/adibM04/AI-Consultant/issues/3) — the sample report is stale,
  and CI hides it by rewriting the file
- [#4](https://github.com/adibM04/AI-Consultant/issues/4) — guard the check count in the
  README and docs against `checklist.json`
- [#5](https://github.com/adibM04/AI-Consultant/issues/5) — the expected-findings test
  skips the hostile repo and every future fixture
- [#6](https://github.com/adibM04/AI-Consultant/issues/6) — link-check the issue
  templates and every example README
- [#7](https://github.com/adibM04/AI-Consultant/issues/7) — write a worked example of
  adding one checklist item

## Next: coverage people ask for

- [#8](https://github.com/adibM04/AI-Consultant/issues/8) — a Vercel stack playbook
- [#9](https://github.com/adibM04/AI-Consultant/issues/9) — a Python/FastAPI fixture
- [#10](https://github.com/adibM04/AI-Consultant/issues/10) — a generated index of all
  193 checks
- [#11](https://github.com/adibM04/AI-Consultant/issues/11) — the `.consultant/` format
  documented for other agents

## Later

- **A command-line path that does not need Claude Code.** The `.consultant/` contract
  ([#11](https://github.com/adibM04/AI-Consultant/issues/11)) is the prerequisite. It
  will still need a model and an API key, and it will never be a free hosted service.
- **More stacks and fixtures**, driven by what users actually deploy. Vercel and Python
  are first because they are the most common gaps.
- **Better reports, not more checks**: clearer fixes, fewer false alarms, a shorter path
  from a finding to a pull request.

## Not doing

- A hosted service that receives your code.
- Automatic fixes applied to your repository.
- SOC 2, HIPAA or "secure" certificates. It is a checklist, not an auditor.
- Telemetry, analytics, or anything that phones home. The repository contains a test
  that would fail.

## How to influence this

1. Comment on the issue you care about with your situation: what you deploy, what broke,
   what the report got wrong. That is worth more than a thumbs-up.
2. Open an [Ideas discussion](https://github.com/adibM04/AI-Consultant/discussions/categories/ideas)
   for something not listed.
3. Propose a checklist item if the gap is a production failure you have seen.
4. Send a pull request. Small and tested beats large and speculative; the rules are in
   [CONTRIBUTING.md](CONTRIBUTING.md), and [docs/development.md](docs/development.md) is
   the map.

If your stack is missing, say so. Most of the open issues exist because someone will
eventually need them, not because they are interesting to build.
