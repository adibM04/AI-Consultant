# Close the unknowns, answer the buyer

## Evidence

Many items cannot be seen from code: has anyone restored a backup, were the leaked keys rotated, does the company own the domain registrar? `/ai-consultant:consult-evidence` walks you through doing it, helps you write an evidence note in `docs/evidence/` (it refuses text that looks like secrets), and records a signed attestation that expires within a year.

Attestations can settle `unknown` items only. They never override a failing finding, never apply to anything checkable in code, and the report lists each one with who said it and when, as a human claim the tool did not verify.

## Questionnaires

`/ai-consultant:consult-questionnaire` maps each question to checklist items and drafts an answer per row. The honesty is enforced in code (`scripts/questionnaire.py`), not by asking the model nicely:

- A stance cannot be stronger than the weakest backing item. One failed control makes "Yes" a "No" or "Partial", whatever the model wrote.
- When the audit overrules a draft, the prose is thrown away and replaced with deterministic text built from the checklist.
- The Evidence column lists only real files and named attestations, and "the audit did not look at this" is shown as *unknown*, never as *N/A*.
- Output is a CSV with the original columns plus the draft, basis, evidence and what you still owe, ready for a person to review. Nothing is sent anywhere.

The most useful part is often the "No" column: the specific gaps standing between you and the signature.

See a real draft in [`examples/real-run/questionnaire`](../examples/real-run/questionnaire).
