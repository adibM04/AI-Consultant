---
name: consult-roadmap
description: Turn the audit report into an ordered, realistic remediation plan with effort sizes, owners and what the founder can safely do with AI help versus what needs a human engineer. Use after the consult skill has produced .consultant/REPORT.md, or when the founder asks "what should I fix first", "make me a plan", or "what do I need to hire for".
argument-hint: "[--issues]"
---

# Consult-roadmap: from findings to a plan

Requires `.consultant/REPORT.md` and `.consultant/findings/*.json`. If missing, tell the founder to run the `consult` skill first and stop. If the report is older than the latest commits (`git log -1 --format=%cs` newer than the report date), say so and suggest a re-audit first.

## Build the plan

Read the findings and `PLUGIN_ROOT/checklist/checklist.json` (`PLUGIN_ROOT` is two directories above this skill's base directory) and write `.consultant/ROADMAP.md`:

1. **Order** by this precedence, not by checklist order:
   1. Anything that is actively exposing customers or money right now: leaked secrets (rotate first), missing authorization on data routes, cross-tenant leaks, unauthenticated admin routes, unverified payment webhooks.
   2. Remaining `critical` items.
   3. Confirmations for critical `unknown` items (these are quick questions, not engineering work, and often unblock the verdict).
   4. `high` items, grouped so related work ships together (for example all auth hardening in one change).
   5. `medium` and `low`, then the deferred "coming up" items by tier.
2. For each work item give: ids covered, what to do in plain words, **size** (S: under half a day, M: 1-3 days, L: a week or more, with the assumption behind the guess), **owner** (role from the item's `role`), and **risk**: `safe with AI + review` or `needs an experienced engineer` (live data migrations, auth/session rewrites, key rotation sequencing, anything touching production data or money).
3. Group into phases: **Now (this week)**, **Before the first paying customer**, **Before you scale**, **Before the enterprise deal**. Phase boundaries follow the item tiers and the profile stage.
4. Add a **Dependencies** line where order matters (rotate keys before making the repo public; add tenant scoping before building the export feature; take a backup before any migration).
5. End with **Who to bring in**: from the open items, which roles are needed, whether as a one-off review, a fractional hire, or a full-time role, and which single hire or contractor would retire the most risk. Be honest if the answer is "a security review by someone independent", since the auditor cannot be its own second pair of eyes.

Keep it to what the report supports. Do not add recommendations for items that were not found open.

## Optional: create issues

Only if the founder passed `--issues` or asks for it: create one GitHub issue per work item (not per checklist id) using the GitHub tools available in the session, with the ids, evidence references, acceptance criteria ("the auditor marks SEC-01 pass"), and labels for phase and severity. Show the list of titles first and confirm before creating anything. Never put secret values in an issue.

## Present

Summarise the first phase in chat (at most about ten bullets) and point to `.consultant/ROADMAP.md`. Offer to start on the safe items, one at a time, with the founder reviewing each change.
