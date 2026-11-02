## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `python3 scripts/dev.py check` passes locally (it is what CI runs, on Linux, macOS and Windows)
- [ ] If `checklist/*.yml` changed: ran `python3 scripts/dev.py build` and committed `checklist/checklist.json`
- [ ] If a skill or `agents/domain-auditor.md` changed: I say below what the eval showed, or why I did not run it
- [ ] No real secrets, customer data, or personal data in a fixture, test, or screenshot
- [ ] If the verdict got more lenient: the reason is stated below

## What the eval showed (skills and auditor prompts)

<!-- `python3 evals/run_eval.py <fixture> --yes` costs money. Write "not run" and why if it was not. -->

## Notes for the reviewer

<!-- Anything that is subtle, or that you are unsure about. "I could not verify X" is useful. -->
