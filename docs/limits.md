# What it cannot do

Be clear-eyed about this:

- It reads code and config. It cannot see your cloud console, DNS, contracts, vendor agreements or who has the pager. Those become questions.
- Scanner and registry checks only cover what is installed and reachable. If a tool is missing the report says that area was not checked, rather than calling it clean.
- It is a language model reading files. It will miss things and occasionally be wrong. Treat a clean report as "no known gaps in what was checked", never as safety.
- It is not a penetration test, an audit, legal advice, or a tax opinion. SOC 2 needs an auditor. HIPAA needs a person accountable for it. GDPR needs a lawyer.
- It does not replace the people in the second half of the original list: a senior engineer to read what the AI wrote, someone to run live-database migrations, an on-call human, someone who remembers why it is built this way. It tells you which of those you need, and how urgently.

## Optional scanners

Needs Python 3 (standard library only). Optional: [gitleaks](https://github.com/gitleaks/gitleaks), [osv-scanner](https://github.com/google/osv-scanner) and [trivy](https://github.com/aquasecurity/trivy) make the secret and dependency checks much stronger. gitleaks and semgrep output have been checked against the real tools; osv-scanner and trivy have not yet.

## Use it with other agents

The skills are plain Markdown prompts and the checklist is plain YAML/JSON. Only the Claude Code plugin packaging is tested. For other tools, point the agent at `skills/consult/SKILL.md` and `agents/domain-auditor.md`, and run `python3 scripts/render_report.py --dir .consultant` yourself. Ports are welcome.
