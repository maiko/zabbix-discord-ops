# Contributing

Keep changes small, tenant-safe, and testable.

Before submitting:

```console
gofmt -w cmd internal
go test -race ./...
go vet ./...
docker build -t zabbix-discord-ops:contributor .
```

New interactive operations must:

- revalidate the live Zabbix event before mutation;
- verify guild, channel, Discord role or user, route tag, required tags, and
  host group;
- write an auditable actor identity to Zabbix;
- include authorization-denial and tamper tests;
- fit within Discord's three-second initial-response window.

Never add real tenant IDs, credentials, event payloads, hostnames, or Zabbix
exports to fixtures or documentation.

Commits and pull requests must explain the security and operator impact.
