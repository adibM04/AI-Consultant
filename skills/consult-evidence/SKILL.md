---
name: consult-evidence
description: Help the founder prove the things code cannot show (a backup restore test, key rotation, who owns the domain registrar, an on-call rota, a vendor agreement) and record each as a signed, expiring attestation so the audit report can close those items. Use when the report has items under "Needs a human to confirm", or when the founder says "I restored the backup", "I rotated the keys", "we have a BAA with X", or asks how to clear the unknowns.
argument-hint: "[ITEM-ID ...]"
---

# Consult-evidence: close the "unknown" items honestly

The report lists items it could not verify from the repository under **Needs a human to confirm**. Some can only be settled by a person doing a thing and writing down what happened. This skill walks the founder through that and records it.

## What an attestation is, and is not

It is the founder's own signed statement ("I restored last night's backup to staging on 2026-09-20; it took 14 minutes; row counts matched") plus an evidence document in the repository. It expires within a year. The tool does not verify it, and the report says so.

It **cannot** replace the code: items checkable in code (injection, authorization, hashing) are rejected, and an attestation never overrides a failing finding. Do not look for ways around that.

## Steps

1. Read `.consultant/REPORT.md` and `.consultant/findings/*.json`. List the open `unknown`/unaudited items whose checklist `evidence` is `process` or `config` (from `PLUGIN_ROOT/checklist/checklist.json`; `PLUGIN_ROOT` is two directories above this skill's base directory). If the user named item ids, use those. Order by severity, critical first. Show at most five at a time with the `question` each finding carries.
2. For each item the founder wants to work on, say plainly **what they need to actually do** if they have not done it yet. Examples:
   - DAT-08 restore tested: restore the latest backup into a scratch database, time it, check row counts or a known record, write down the steps.
   - SEC-02 keys rotated: list every key that ever appeared in a commit, chat or screenshot, rotate each in its provider's console, note the date.
   - OPS-04 accounts owned by the company: list registrar, DNS, cloud, git host, payment provider and the owning account for each.
   - CMP-02 BAAs: list every vendor that touches patient data and the signed agreement for each.
   Do not nudge them to say it is done if it is not. An honest "not yet" stays `unknown`, and that is fine.
3. When they have done it, help them write the evidence document at `docs/evidence/<ITEM-ID>-<short-slug>-<YYYY-MM>.md`: what was done, by whom, on what date, the result, and links to dashboards or tickets. A screenshot may be committed beside it (`docs/evidence/*.png`).
   - **Redact secrets.** Never paste keys, tokens, passwords, connection strings or customer data into an evidence file. Describe them ("rotated the Stripe secret key") and screenshot only pages without secrets. The attest script refuses text files that look like they contain secrets, and cannot scan images, so check those by eye.
4. Only when the founder has confirmed, in this conversation, that the thing was really done and when, record it:

   ```
   python3 "$PLUGIN_ROOT/scripts/attest.py" add --item DAT-08 --by "<their name>" \
       --note "<one or two sentences: what was done, when, the result>" \
       --evidence docs/evidence/DAT-08-restore-2026-09.md
   ```
   `--by` must be the person making the statement. Use the name they give you, never yours and never a guess. The script refuses unknown items, code-checkable items, missing evidence files, text that looks like secrets, and items the code audit already marked fail or partial.
5. Re-render: `python3 "$PLUGIN_ROOT/scripts/render_report.py" --dir .consultant`, then tell the founder what changed in the verdict and what is still open.
6. Remind them that attestations expire (the report shows the date) and that `.consultant/attestations.json` and `docs/evidence/` should be committed so a pull-request reviewer, or the PR guard, can see changes to them.

## Rules

- **Never attest on the founder's behalf from inference.** If they have not said it happened, do not record it. A plausible guess is not evidence.
- Do not write evidence documents that state facts you were not told. Quote the founder's words; do not embellish.
- Do not modify application code in this skill.
