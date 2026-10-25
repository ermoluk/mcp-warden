# Open-core commitment

This document describes how `mcp-warden` is funded and what we promise
about the relationship between the open-source binary and any future
commercial offerings.

## What stays free forever

- The CLI binary, MCP server, and every single-user feature.
- The OS keychain integration, local audit log, local approval flow, and
  local presets.
- All features that exist in the OSS binary at the time of any future
  commercial launch — **no rug-pulls**, no relicensing of features
  already shipped.
- Source code under the **Apache-2.0** license. The patent grant matters
  for security tooling; we won't move to AGPL or a proprietary EULA on the
  core.

## Where future paid services may attach

`mcp-warden` is built around four trait abstractions — `KeychainStore`,
`ApprovalTransport`, `AuditSink`, `PresetSource` — each shipping with one
local implementation in OSS. Any paid offering attaches as an *additional*
implementation behind the same trait, never as a gate on the existing one.

The categories of future paid services that genuinely require infrastructure
or coordination:

- **Hosted approval relay.** Mobile push notifications and remote approval
  require a backend, signed mobile apps, and APNs/FCM credentials.
  Encrypted relay (we never see the secret, only signed approval requests).
  Self-hosting is and will remain possible for technically inclined users.
- **Team mode.** Centralized preset management, shared audit logs across a
  team, approval routing (e.g. `deploy-prod` prompts the on-call engineer),
  SSO / SCIM, multi-approver workflows. Solves problems that exist only
  when more than one human is involved.
- **Compliance and enterprise.** SOC2 evidence packs, SIEM forwarding,
  custom approval workflows (Jira / ServiceNow), SLA-backed support.

If something can be done locally with one user on one laptop, it stays in
the OSS binary.

## Funding before paid services exist

- GitHub Sponsors and OpenCollective for individual and organisational
  donations.
- Sponsorware tiers for company logos in the README. No code changes, no
  feature gating tied to sponsorship.

## Anti-patterns we are explicitly avoiding

- **Open-source bait-and-switch.** No relicense after gaining adoption.
  The Apache-2.0 commitment is permanent for the core.
- **Crippling OSS to drive paid upgrades.** Paid features must be additive
  (require infrastructure or coordination), not subtractive (gates on
  features that already work locally).
- **Premature monetization.** No paid tiers before there's a clear
  "I'd pay for this" signal from real users. Selling too early kills
  momentum.
- **Vendor lock-in in the protocol.** No proprietary extensions to MCP.
  The OSS binary speaks vanilla MCP so users can switch agents freely.

## License

Apache-2.0. See `LICENSE`.

We don't plan to relicense the core. If we ever distribute closed-source
modules, they live in a separate repository, are clearly labelled, and link
against the OSS `mcp-warden-core` library — the same open-core pattern
Sentry, GitLab, and Cal.com use.
