# How it works

```
founder ──► consult skill ──► profile.json (stage + tags, detected and confirmed)
                │
                ├─► deterministic facts ──► facts/stacks.json     which playbooks apply
                │                           facts/packages.json   does every dependency exist?
                │                           facts/scanners.json   gitleaks / osv-scanner / trivy
                │
                ├─► domain-auditor × 14, in parallel, read-only ──► findings/<domain>.json
                │        (reads the facts and the matching stack playbooks)
                │
                └─► scripts/render_report.py (deterministic) ──► REPORT.md
```

## Deterministic facts under the model

Scripts produce facts; the model interprets them. Nothing here is installed or executed from your project.

| Script | What it establishes |
|---|---|
| `scripts/verify_packages.py` | Whether every npm / PyPI dependency exists, and flags hallucinated names (`NOT_FOUND`), look-alikes of popular packages (`TYPOSQUAT_SUSPECT`), brand-new or abandoned packages. Sends **package names only** to the public registries; `--offline` sends nothing. |
| `scripts/run_scanners.py` | Runs gitleaks, osv-scanner and trivy if you have them (semgrep with `--semgrep`), normalises the output, and strips secret values. Missing tools are reported with install hints, never installed. |
| `scripts/attest.py`, `scripts/questionnaire.py` | Attestations with validation and secret screening; honesty-capped questionnaire drafts |
| `scripts/pr_guard.py` | The deterministic pull-request checks behind the GitHub Action |
| `scripts/detect_stacks.py` | Detects Supabase, Firebase, Next.js, Stripe and AI-builder exports, so the auditors apply the right playbook |

## Stack playbooks

[`stacks/`](../stacks/) holds concrete, checklist-mapped procedures for the platforms where vibe-coded apps fail most often: Supabase (RLS off, `service_role` in the browser), Firebase (open rules, "authenticated" mistaken for "authorised"), Next.js (Server Actions without auth, secrets in `NEXT_PUBLIC_`, middleware-only auth), Stripe (unverified webhooks, client-chosen prices), and AI-builder or agent-written codebases (prototype debris, secrets that passed through a chat). Two deliberately broken fixtures in [`examples/`](../examples/) check that they work.

## Design choices worth knowing

- **The checklist is data, not prompt.** YAML in, JSON out. You can fork it for your own industry.
- **The verdict is code, not vibes.** `render_report.py` computes it with tested rules: any failing critical item means `NOT READY`; a critical item nobody could verify means `NOT VERIFIED`.
- **`pass` needs evidence.** A finding that says "pass" without a `file:line` is downgraded to `unknown`.
- **Defences live in code, not just prompts.** A `pass` must cite a real file and line, and waivers need a person, a creation date and a short expiry, so a hostile repo cannot plant its way to `READY`. [`evals/`](../evals/) runs the real consultant against a deliberately hostile repository to check this.
- **Honest about the invisible.** Items that need a console, a contract or a person are `unknown` with a specific question, never assumed fine.
- **Audited repos are untrusted input.** The auditor is instructed to treat READMEs and comments as data, never commands, to stay read-only, and never to copy a secret into a report.
- **Re-runs diff.** The report shows what you fixed and what regressed. Accepted risks go in `waivers.json` with a reason and an expiry, and reopen when they expire.

## Examples

See a real run in [`examples/real-run`](../examples/real-run) (model-generated, against the deliberately broken [`examples/vibe-coded-app`](../examples/vibe-coded-app)). [`examples/sample-output`](../examples/sample-output) is a small hand-written file used only to test the renderer.
