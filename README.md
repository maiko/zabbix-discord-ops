# Zabbix Discord Ops

Zabbix Discord Ops adds tenant-aware, interactive incident operations to
Discord without making Discord a source of truth.

It sends Zabbix problems to the correct Discord channel and lets authorized
operators acknowledge, comment on, suppress, change severity, unsuppress, or
manually close a problem. Every interaction re-reads the live Zabbix problem
and revalidates the Discord guild, channel, user or role, Zabbix event tags,
and Zabbix host group before changing anything.

## Security model

The service is deliberately split into two trust boundaries:

- `POST /discord/interactions` is the only public endpoint. Discord requests
  require a valid Ed25519 signature, a fresh timestamp, and replay protection.
- `POST /v1/zabbix/events`, `GET /healthz`, and `GET /metrics` remain on
  loopback. Zabbix event ingestion also requires an independent bearer token.

Buttons carry a compact HMAC-authenticated event, route, action, and expiry.
They are not authorization grants. Authorization is recalculated from live
Discord and Zabbix state on every click and modal submission.
Mutating interactions acknowledge Discord immediately with an ephemeral
deferred response, then publish the result after the live authorization and
Zabbix operation finish. This keeps slow upstream calls outside Discord's
three-second initial-response deadline.
If Zabbix does not confirm a mutation response, the bot reports an unknown
outcome and tells the operator to inspect the event instead of retrying a
possibly completed action. Graceful shutdown drains in-flight interactions.

The service has no database, accepts no Discord message content, does not need
privileged intents, and stores no credentials in its JSON configuration. It
does persist event, route, channel, message, and pending-at metadata in a small
directory of atomic JSON records so notification correlation survives process
restarts without a database.
Replay entries live in process memory until Discord's five-minute signature
window closes. A process restart clears that cache, so repeated Zabbix comments
can still be submitted if Discord replays the exact interaction across a
restart. The signed timestamp window, live authorization checks, and Zabbix
audit history remain enforced; operators should inspect Zabbix before retrying
an interaction after a bot restart.

## Supported operations

- Alert lifecycle: create, update, and resolve the original Discord message.
- Interactive actions: acknowledge, comment, suppress, unsuppress, change
  severity, and manually close.
- Slash commands:
  - `/zabbix status`
  - `/zabbix problems`
- Prometheus text metrics on the loopback `/metrics` endpoint.

Manual close still depends on the underlying Zabbix trigger allowing manual
close. Zabbix rejects the action if the trigger policy forbids it.

## Routing

Each route is fail-closed and binds all of the following:

- one Discord guild;
- one Discord channel;
- at least one permitted Discord role or user;
- required Zabbix event tags;
- at least one permitted Zabbix host group ID.

The event must also contain the configured routing tag. A typical route uses
`notification_route=customer_prod`, `tenant=customer`, and `impact=prod`,
plus the numeric ID of `Tenants/Customer`.
If the routing tag, a configured required tag, or a Discord correlation tag
has multiple distinct values, ingestion and live interaction authorization
reject the event instead of depending on Zabbix API ordering. Other Zabbix
tags remain multi-valued.

See [`config.example.json`](config.example.json).

## Build and test

The project requires Go 1.26.5 or newer. The patch floor is intentional:
earlier 1.26 toolchains contain reachable standard-library vulnerabilities.

```console
go test -race ./...
go vet ./...
go build ./cmd/zabbix-discord-ops
go build ./cmd/register-commands
```

The container uses a pinned Go 1.26.5 / Alpine 3.24 builder and a `scratch`
runtime. It runs as UID/GID 65532, contains only the binary and CA bundle, and
has a native healthcheck.

```console
docker build \
  --build-arg VERSION=dev \
  --build-arg GIT_SHA="$(git rev-parse HEAD)" \
  --build-arg CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t zabbix-discord-ops:dev .
```

## Discord application

Create a Discord application and bot with these scopes:

- `bot`
- `applications.commands`

The bot needs only `View Channels`, `Read Message History`, `Send Messages`,
and `Embed Links` in its destination channels. Read history is used only to
recover a message accepted by Discord if the process stopped before recording
its message ID. Do not grant Administrator or privileged gateway intents.
Set `discord_bot_user_id` to this bot user's numeric ID. Reconciliation accepts
only messages authored by that exact bot, because Discord nonce uniqueness is
scoped to the author.

Each route has one interactive `channel_id` and may define
`mirror_channel_ids`. Mirrors receive the same problem, update, and recovery
cards without interactive components. This supports a private global
operations channel plus read-only tenant channels without granting tenant
members mutation rights. The bot needs the same channel permissions in every
mirror.

Set the application's interaction endpoint to:

```text
https://YOUR_PUBLIC_HOST/discord/interactions
```

The Nginx location in
[`deploy/nginx/discord-interactions.location.conf`](deploy/nginx/discord-interactions.location.conf)
publishes only that endpoint. If the service is behind Coolify, expose the
same single path through Traefik.

Register commands first against a test guild, where changes are immediate:

```console
go run ./cmd/register-commands \
  -application-id 000000000000000001 \
  -guild-id 000000000000000002 \
  -token-file /secure/path/discord-bot-token
```

The token file must be a regular file with no group or world access. Omit
`-guild-id` only after canary validation to register the global command. New
commands default to no member permission; explicitly grant the same Discord
roles configured in each route.

## Zabbix setup

### API identity

Create a dedicated Zabbix user and API token. Do not reuse an administrator
or the Rudder synchronization identity.

Give its user group read-write access only to the host groups referenced by
routes. Zabbix requires read-write trigger rights to change severity or
manually close an event. This does not grant configuration APIs: the role's
API allowlist remains limited to:

- `problem.get`
- `trigger.get`
- `host.get`
- `event.acknowledge`

`apiinfo.version` is called without authorization, as required by Zabbix 7.4.

The role still needs the UI action permissions corresponding to acknowledge,
comment, severity changes, suppression, and manual close. Keep frontend access
disabled. Zabbix 7.4 requires a User role to retain at least one UI entry, so
enable only `monitoring.problems`; the frontend-disabled user group still
prevents login. Disable every other role action and UI entry, every module, and
all service access. A new route must not ship until its exact host group has
been added to both the bot configuration and this dedicated user group's
rights.

### Media type

Import
[`deploy/zabbix/media_zabbix_discord_ops.yaml`](deploy/zabbix/media_zabbix_discord_ops.yaml).
It imports disabled.

Define:

- `{$ZABBIX_DISCORD_OPS_URL}` as
  `http://127.0.0.1:9088/v1/zabbix/events`;
- `{$ZABBIX_DISCORD_OPS_INGEST_TOKEN}` as a secret-text macro containing the
  same ingest credential loaded by the service;
- `{$ZABBIX.URL}` as the canonical HTTPS frontend URL.

The webhook rejects non-trigger events, non-loopback destinations, and HTTP
proxies. It returns the primary Discord message correlation IDs as Zabbix
event tags, so recovery and update operations edit the original message.
Mirror message IDs remain in the private correlation store and are updated in
the same ingest transaction.

Before problem creation, the service durably records a pending event. It then
uses the numeric Zabbix event ID as a Discord nonce with `enforce_nonce`
enabled and atomically stores the returned message ID. If the process stops in
that narrow window, the next attempt scans Discord messages created since the
pending record and recovers the matching nonce before deciding whether a
message still needs to be sent. Completed correlations are reused across
retries and restarts. Same-event work is serialized by a context-aware keyed
lock; unrelated events remain concurrent and a queued request cannot outlive
its ingest deadline.

The imported media type explicitly uses three attempts at ten-second
intervals. The ingest handler applies an eight-second deadline to request-body
reading and all upstream work, below the media type's ten-second timeout.
Do not delete the correlation state while alerts are active. If it is lost,
only Discord's short nonce uniqueness window remains and a sufficiently
delayed retry can create a duplicate.
`state_review_after_days` (90 by default, configurable from 30 to 3650 days)
defines when a completed record is considered stale. Startup and daily
inspections validate every record, log the stale count, and publish it as
`zabbix_discord_ops_stale_completed_correlations`; they never delete state.
Pending and completed records remain available until an operator reviews exact
targets and performs an explicit, backed-up cleanup. Run only one active
service instance per state directory.
Reconciliation scans newest-to-oldest messages back to five minutes before the
pending timestamp and remains inside the eight-second ingest budget. After a
long Discord outage or in an unusually high-volume channel, that scan may time
out before reaching the boundary. The service then fails closed and leaves the
pending record untouched; it does not create a speculative replacement.
Restore Discord access or investigate that pending record before retrying.

Create one dedicated notification user with this media type. Do not put the
ingest token in the media "Send to" field.

### Action design

Use one trigger action for the media type and enable problem, recovery, and
update operations. Avoid invoking this webhook from multiple actions for the
same event because Zabbix webhook correlation tags are event-scoped.

Keep severity, tenant, impact, and time-window decisions in Zabbix actions:

- default routes: notify only in their local operating window;
- production routes: notify 24/7;
- Discord: Warning and above;
- Pushover: High and Disaster according to the separate escalation policy.

The bot enforces destination and operator authorization. It does not
reimplement the Zabbix escalation engine.

## systemd deployment

The recommended deployment is the hardened systemd service in
[`deploy/systemd/zabbix-discord-ops.service`](deploy/systemd/zabbix-discord-ops.service).
It uses `DynamicUser`, a read-only filesystem, an empty capability set, and
encrypted systemd credentials.

Install the non-secret config as:

```text
/etc/zabbix-discord-ops/config.json
```

Set `state_path` to
`/var/lib/zabbix-discord-ops/correlations`. The unit creates the private,
writable parent state directory for its dynamic user, and the service creates
the correlations subdirectory with mode `0700`. The records contain no
credentials, but they are operational state: preserve them across upgrades and
include the directory in host backups.

Provision these systemd credential names:

- `discord-bot-token`
- `discord-public-key`
- `zabbix-api-token`
- `ingest-token`
- `component-signing-key`

The Discord public key is a 32-byte hex string. Generate independent 32-byte
hex values for the ingest and component-signing credentials. Never reuse a
Discord or Zabbix token for either purpose.

Use `systemd-creds encrypt --name=NAME - DESTINATION` to write each secret
directly to the matching file under `/etc/credstore.encrypted`; feed the value
through standard input from a password manager or a non-logged prompt. The
service unit maps those files into `$CREDENTIALS_DIRECTORY`.

Before enabling:

```console
systemd-analyze verify /etc/systemd/system/zabbix-discord-ops.service
nginx -t
systemctl daemon-reload
```

Start with a single non-production route and synthetic Zabbix event. Validate
problem creation, acknowledge, comment, suppression, severity change,
recovery, route rejection, and an unauthorized Discord role before expanding
coverage.

## Container deployment

The process intentionally binds only an IP loopback address. On a Linux Docker
host, use host networking so host Nginx and Zabbix can reach that loopback
socket. Keep the root filesystem read-only, drop all capabilities, set
`no-new-privileges`, mount a read-only config plus a read-only credential
directory, and mount a dedicated writable directory at
`/var/lib/zabbix-discord-ops` for correlations. A bridged container with
`0.0.0.0` is intentionally unsupported.

## Release verification

Tagged releases publish:

- Linux `amd64` and `arm64` binaries;
- SHA-256 checksums;
- an SPDX JSON SBOM;
- signed GitHub build provenance;
- multi-architecture GHCR images with BuildKit SBOM and provenance
  attestations.

Verify a downloaded binary:

```console
sha256sum --check checksums.txt
gh attestation verify zabbix-discord-ops_linux_amd64 \
  --repo maiko/zabbix-discord-ops
```

Verify an image:

```console
gh attestation verify \
  oci://ghcr.io/maiko/zabbix-discord-ops-container:VERSION \
  --repo maiko/zabbix-discord-ops
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
