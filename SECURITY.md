# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting for this repository. Include the
affected version, impact, reproduction steps, and any proposed mitigation.
Credentials, webhook payloads, tenant identifiers, and Zabbix exports must be
redacted.

You should receive an initial triage response within five business days. A
fix, coordinated disclosure date, and credit will be discussed privately.

## Supported versions

Security fixes are applied to the latest tagged release. Deployments should
pin a release or image digest and consume new patch releases promptly.

## Threat model

The main security boundaries are documented in the README. In particular:

- only Discord's signed interaction endpoint may be public;
- Zabbix ingestion and metrics must remain on loopback;
- route authorization requires Discord identity, Zabbix tags, and Zabbix host
  group membership;
- secrets must be loaded from protected credential files, never JSON config,
  command-line flags, container build arguments, or Git.

Discord signature replay entries are process-local and expire at the end of
the signed request's five-minute acceptance window. Restarting the service
clears those entries. Zabbix notification correlation is persisted before
delivery and completed with the Discord message ID. A pending record is
reconciled against Discord message history by author, nonce, and creation
window after a restart. Completed records have a configurable bounded
review age; pending and completed records are never automatically deleted.
Startup and daily inspection are read-only. Keep the state directory durable
and private; deleting it removes the durable duplicate delivery protection.
Interactive comments may still be repeated across a restart and remain visible
in the Zabbix audit history.
