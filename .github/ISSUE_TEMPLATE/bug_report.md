---
name: Bug report
about: Something does not work as documented
labels: bug
---

**Do not include API tokens, real internal hostnames, or other secrets.** Redact
real domains/addresses with documentation placeholders (`example.com`, `192.0.2.x`).

### What happened

A clear description of the problem and what you expected instead.

### Version

Output of `splitdnsd -version` (and the package version if installed from the `.deb`).

### Config (redacted)

The relevant `[section]`s of your config with secrets and real names removed, plus
the output of `splitdnsd -check-config`.

### Reproduction

Steps and the exact queries (`dig …`) that show the issue, with the answers you got
vs. the answers you expected.

### Logs

Relevant `journalctl -u splitdnsd` lines (redacted).
