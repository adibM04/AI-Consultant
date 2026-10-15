---
name: consult-audit
description: Re-audit one or more domains of the production-readiness checklist (identity, authorization, data, payments, security, compliance, infrastructure, observability, testing, integrations, ai-features, ux, maintainability, operations) and refresh the report. Use after fixing issues to confirm they are closed, or when the founder wants a deep look at one area such as "check my auth" or "is my billing safe".
argument-hint: "<domain> [domain ...]"
---

# Consult-audit: targeted re-audit

Use this after fixes, or for a focused look at one area. It needs an existing `.consultant/profile.json`; if there is none, tell the founder to run the `consult` skill first (it builds the profile) and stop.

## Steps

1. `PLUGIN_ROOT` is two directories above this skill's base directory. Read `PLUGIN_ROOT/checklist/checklist.json` to get the valid domain ids. Match the arguments against them (accept an item id such as `SEC-01` too, and expand it to its domain). If no argument was given, ask which domain, listing the ids with their titles.
2. Read `.consultant/profile.json`. Tell the founder in one line which items of the domain are in scope for their stage and tags, and how many are deferred.
3. Refresh the facts the domain depends on (for `security`, `maintainability`, `infrastructure`, `integrations`: all three scripts from the `consult` skill, step 2; for any other domain `detect_stacks.py` is enough, and run the rest if `.consultant/facts/` is missing or older than the latest commit). Delete `.consultant/findings/<domain>.json` for each requested domain, then spawn one `domain-auditor` subagent per domain **in a single message**, passing `domain`, absolute `plugin_root`, the absolute path to the profile, and the absolute path to `.consultant/facts/`.
4. Run `python3 "$PLUGIN_ROOT/scripts/render_report.py" --dir .consultant`.
5. Summarise only what changed for those domains, using the "Since the last run" section of `.consultant/REPORT.md`: items now closed, items still open, regressions. If something the founder claims to have fixed is still failing, say exactly where and why, with `path:line`.

## Rules

- Never mark an item fixed because the founder says it is. The auditor re-checks the code.
- Items that need a process or console check stay `unknown` until the founder supplies evidence. Offer to record it: for example, a restore-test log committed under `docs/`, or a screenshot referenced from `docs/evidence/`, which the auditor can then cite.
- Do not modify application code in this skill.
