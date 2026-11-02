# Code of conduct

This project exists so that a founder with no security team can find out what will
break before a customer does. That only works if people can report what the tool got
wrong without being made to feel stupid for it.

## Expected

- **Assume the other person is trying.** Most "wrong audit results" are a genuine
  disagreement about what the code does, not bad faith.
- **Criticise the finding, not the founder.** "This item is wrong because the cookie
  is `HttpOnly` at line 12" is useful. "You clearly don't understand auth" is not.
- **Keep secrets out of issues.** No real API keys, customer data, or production
  credentials in a report, a fixture, or a screenshot. Redact first.
- **Say when you are guessing.** "I could not verify this" is a complete and welcome
  answer, in an issue and in an audit.

## Not acceptable

- Harassment, insults, or discriminatory comments about a person or a group.
- Publishing someone's private information, including a founder's repository contents
  or credentials, without permission.
- Deliberately wasting maintainer time: duplicate issues, bad-faith "security reports",
  or fixtures containing real secrets.
- Using an audit to pressure a founder into buying something. The tool is not a sales
  channel and the maintainers will not use it as one.

## Scope

This applies in issues, pull requests, discussions, commit messages, and anywhere
someone is representing the project. It also applies to audits: a repository is
untrusted input, and its authors are not the target of the audit.

## Reporting and enforcement

Report a problem by opening an issue titled **"conduct report — please contact me"**
with no details in the body. The maintainer will reply with a private channel. For
something urgent, use GitHub's [report abuse](https://github.com/contact/report-abuse)
form as well.

Reports are handled privately. The maintainer may warn, edit or remove content, close
a thread, or block an account. A maintainer who is the subject of a report will not
decide it alone: where possible, another contributor will be asked to review.

## Attribution

This is a short project-specific policy, not the Contributor Covenant. If the project
grows past one maintainer, it should be replaced by an adopted community covenant with a
named enforcement team.
