# Security policy

`mcp-warden` is a credential broker, so security reports are the most
valuable contribution you can make.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Include what you can: affected version, a description of the issue, steps to
reproduce, and the impact you believe it has. You should get an initial
response within a few days.

## Scope

In scope — anything that breaks the invariants in
[`CLAUDE.md`](CLAUDE.md#security-invariants--non-negotiable) and
[`docs/threat-model.md`](docs/threat-model.md), for example:

- a secret value reaching the agent, logs, audit log, error messages or
  tool descriptions;
- an action running without the approval its policy requires;
- an allow-list bypass (HTTP path/method, SSH command regex, SFTP path,
  DB named query);
- tampering with or deleting audit log entries through `mcp-warden`;
- the web UI becoming reachable from anything other than loopback.

Out of scope — a compromised OS user account or keychain, and an agent using
permissions a preset legitimately grants.

## Supported versions

Only the latest release receives security fixes.
