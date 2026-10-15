# Vibe-coded fixture app

A tiny Express server written to contain the classic weekend-prototype mistakes. It exists so that
contributors can check that the consultant's auditors catch real problems.

**It is intentionally insecure. Do not run it anywhere public.** The "Stripe key" in it is a fake string.

`expected-findings.json` lists what a competent audit should flag, by checklist id and file line.
Auditors may legitimately flag more, but should not pass any of these.
