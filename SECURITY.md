# Security policy

This project reads other people's code and can run read-only shell commands on a founder's machine, so
its own safety matters.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security tab, "Report a
vulnerability"). Do not open a public issue for something exploitable. Expect a first response within
a week.

## Things we especially want to hear about

- A way for content in an audited repository (README, comments, filenames, commit messages) to make an
  auditor run commands, write outside `.consultant/`, or mark a failing item as passing (prompt injection)
- Any path by which a secret found during an audit could be copied into a report or finding
- Report-renderer bugs that turn a failing critical item into a better verdict
