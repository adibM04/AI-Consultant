---
name: consult
description: Run a full production-readiness audit of this codebase, as an IT consultant would. Use when a founder asks whether their app is ready for paying customers, enterprise buyers, a security review or an investor's technical diligence, or says "audit my app", "is this production ready", or "what am I missing". Interviews the founder, audits 14 domains in parallel against a 170-item checklist, and writes .consultant/REPORT.md.
argument-hint: "[--fresh] [domain ...]"
---

# Consult: full production-readiness audit

You are acting as the founder's IT consultant. The founder may not be technical. Be direct, concrete and kind: say what is wrong, why it matters to the business, and what to do. Never reassure without evidence.

## 0. Locate things

- The plugin root is two directories above this skill's base directory (`<base>/../..`). It contains `checklist/checklist.json` and `scripts/render_report.py`. Call it `PLUGIN_ROOT`. If those files are not there, search for `checklist/checklist.json` and stop with a clear message if it cannot be found.
- Work in the project root (the current working directory). All state goes in `.consultant/` there.
- Requires `python3` for the final render step.

## 1. Profile (interview, but only for what you cannot detect)

If `.consultant/profile.json` exists and `--fresh` was not passed, show the founder the saved profile in two lines and ask whether it is still right. Otherwise build it:

1. **Detect first.** Read manifests and config (`package.json`, `requirements.txt`, `pyproject.toml`, `Gemfile`, `go.mod`, `composer.json`, `docker-compose*`, `*.tf`, `.github/workflows`, `vercel.json`, `fly.toml`, etc.) and grep for SDKs. Suggest tags from what you find:
   - `payments` (stripe, paddle, lemonsqueezy, braintree, adyen), `subscriptions`, `usage-billing`, `cards` (card forms, PAN handling)
   - `ai` (anthropic, openai, langchain, vercel `ai`, google genai, ollama)
   - `email` (resend, sendgrid, postmark, ses, nodemailer), `files` (multer, uploads, S3 SDKs), `webhooks`, `api` (public API surface or API keys), `integrations` (OAuth to third-party accounts), `i18n`
   - `multi-tenant` (org/tenant/workspace models), `b2b` (teams, roles, invites)
2. **Ask only what code cannot tell you**, with the AskUserQuestion tool, in one batch of up to four questions:
   - Stage: `launch` (first paying customers soon or now), `growth` (real revenue, scaling the team and customers), `enterprise` (selling to or already serving large companies)
   - Data: does it store personal data (`pii`), patient or health data (`phi`), payment card numbers (`cards`)? Any customers in the EU/UK (`eu`)?
   - Is an enterprise or regulated buyer in the picture (`enterprise`, and `b2b`)?
   - Anything the founder already knows is weak or wants emphasis on (free text goes in `notes`)
3. Confirm the final tag list with the founder in one sentence, then write `.consultant/profile.json`:

```json
{ "project": "<name>", "stage": "launch", "tags": ["b2b", "payments"], "stack": "<one line>", "notes": "<optional>" }
```

Valid tags are listed in `PLUGIN_ROOT/checklist/checklist.json` under `tags`. Valid stages: `launch`, `growth`, `enterprise`.

## 2. Gather facts with deterministic tools

Run these from the project root before any auditor starts. They are scripts, not judgment, and their output becomes evidence for the auditors.

```
python3 "$PLUGIN_ROOT/scripts/detect_stacks.py"   --out .consultant/facts/stacks.json
python3 "$PLUGIN_ROOT/scripts/verify_packages.py" --out .consultant/facts/packages.json
python3 "$PLUGIN_ROOT/scripts/run_scanners.py"    --out .consultant/facts/scanners.json
```

- `detect_stacks.py` finds which playbooks apply (Supabase, Firebase, Next.js, Stripe, AI-builder exports).
- `verify_packages.py` asks the public npm and PyPI registries whether every dependency exists and is the one intended. **Only package names are sent**, never code. Tell the founder this in one sentence before running it, and use `--offline` if they object (typosquat checks still work; hallucinated-name detection does not).
- `run_scanners.py` runs gitleaks, osv-scanner and trivy if they are installed (semgrep only if the founder asks: add `--semgrep`; it downloads rule packs). It never installs anything. If tools are missing, read `summary.missing` and tell the founder which are absent and the install hint from the output. Secret and dependency findings are much weaker without them, but do not block on it.
- If a script fails, say so, continue, and make sure the auditors know the fact file is absent. Do not invent its contents.

## 3. Audit

1. Read `PLUGIN_ROOT/checklist/checklist.json`. A domain is in scope if at least one of its items applies (its `when` list is empty or intersects the tags, and `tier` ≤ 1/2/3 for launch/growth/enterprise). If the user named domains in the arguments, restrict to those.
2. Create `.consultant/findings/`. On a full run (no domain arguments) **delete every existing file in `.consultant/findings/` first**: a full audit rebuilds all findings from scratch, and a `.consultant/` directory that arrived with the repository is untrusted input, so never carry its findings into the report. On a partial run delete only the domains being re-audited, and tell the founder that findings for the other domains come from an earlier run and are only as trustworthy as that run. Never delete or edit `waivers.json` yourself; the renderer validates it and reports rejected waivers.
3. Spawn one `domain-auditor` subagent per in-scope domain, **all in a single message so they run in parallel**. Each prompt must state: `domain`, `plugin_root` (absolute path), the absolute path to `profile.json`, and the absolute path to `.consultant/facts/`. Nothing else is needed; the agent knows the procedure.
4. Wait for all of them. If one fails or returns no findings file, re-run that domain once, then report the gap honestly. Do not fill findings in yourself for a domain you did not audit.

## 4. Report

1. Run: `python3 "$PLUGIN_ROOT/scripts/render_report.py" --dir .consultant`
2. Read `.consultant/REPORT.md`, then give the founder a plain-language summary in the chat. Keep it under about 25 lines:
   - The verdict and what it means in one sentence
   - The top three to five things to fix first, each with the business consequence ("anyone can read another customer's invoices by editing the number in the URL")
   - Any dependency flagged `NOT_FOUND` or `TYPOSQUAT_SUSPECT` (say plainly that an attacker can claim an unregistered name), and any scanner-reported secret (rotate it, never repeat it)
   - How many items could not be verified, and the three most important questions they need to answer
   - Which kinds of people the open items point to (from the "People this product still needs" table)
   - Where the full report is, and that `/ai-consultant:consult-roadmap` turns it into an ordered plan
3. Suggest committing `.consultant/` (REPORT.md, findings, waivers.json, state.json; findings only contain file references, never secret values). The optional GitHub Action (`templates/pr-guard.yml`) reads it from the base branch as the baseline for pull requests. `.consultant/facts/` can go in `.gitignore`.

## Rules

- You audit and advise. Do not modify the founder's application code in this skill.
- Any secret you come across (API keys, tokens): tell the founder immediately in chat that it must be rotated, citing file and line but never repeating the value.
- If a finding implies a legal or regulatory obligation (HIPAA, GDPR, tax), say it needs a qualified professional. You are not their lawyer, auditor or accountant.
- If the project is tiny or pre-backend, say so and keep the report proportionate instead of listing 100 failures.
