# Runbook

## Start up

At start the connector:

1. reads its configuration from the environment (`DATABASE_DSN` must be set, though nothing uses
   it);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. sets up the client for the vault at `VAULT_ADDR` (the connection is made lazily, on the first
   call);
4. loads the worker token: the file at `CONNECTOR_TOKEN_FILE`, or the dev token;
5. starts the worker, which polls straight away and then every 30 seconds;
6. serves the health services on `GRPC_PORT`.

A failure in steps 1 to 4 (a missing `DATABASE_DSN`, a malformed `VAULT_ADDR`, a token file path
outside the rules, or a missing or empty token file), or a server error, is logged at fatal level
and the process exits non-zero. The vault being down doesn't stop the connector: each poll logs a
warning (`claim due heartbeats`, `claim due rotations`) and the next poll tries again.

## Health

Use the standard gRPC health check:

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

The health check says the process is up. It doesn't say the vault is reachable or the token is
accepted; the warnings in the log do.

## Each poll

A poll runs the due heartbeats, then the due rotations, one job at a time. Each job has its own
time limit (20 seconds for a heartbeat, 30 for a rotation), so one slow target can't hold up the
rest of the batch. A failure on one job is logged with its `secret_id` and never stops the others.

Run more than one connector if one can't keep up; the vault hands each due job to one claimant.

## Rotation safety

- The connector changes a password only by signing in as the account with its current password.
  It never uses an administrative reset, so it needs no rights on the directory beyond the
  account's own.
- The domain's built-in Administrator (RID 500, matched by `objectSid` even when renamed) is never
  changed. Its rotation is reported `SKIPPED` with the reason "built-in Administrator account
  (RID 500), rotation is not allowed". If `objectSid` can't be read, the rotation fails and nothing
  is changed. Heartbeats on the account still run.
- Accounts with `adminCount` set (protected-group members) rotate normally with the self-service
  change.
- The new password is only reported good after a sign-in with it succeeds, over Kerberos when the
  target has a realm. A change that went through but couldn't be validated is reported with change
  `OK` and validate `FAILED`, so the vault can tell the two apart.

## TLS to targets

LDAPS checks the target's certificate against the system roots. A directory with a self-signed
certificate needs its CA trusted in the image. `CONNECTOR_TLS_INSECURE=true` turns the check off
for a test directory only.

SSH heartbeats connect only to a host that presents one of the target's pinned host keys, the same
check the SSH broker makes. The vault sends the pins with each job. The check runs during key
exchange, before the account's key is offered, so a host that isn't verified never sees it. A
heartbeat proves the key is accepted and runs no command.

- A target with no pins (or none that parse) reports `host key not pinned for this target`.
- A host whose key matches none of the pins reports `host key mismatch`.

Neither is a failed credential: the vault records them as their own results and doesn't pause the
heartbeat for them. Both details name the presented key's SHA256 fingerprint, never key material.
Pin the target in the vault (site admins only) with the key's authorized_keys line.

## Troubleshooting

| Log message | Meaning |
|---|---|
| `claim due heartbeats` or `claim due rotations` (warn) | The vault is unreachable, or refused the token. The error says which (`Unavailable`, `PermissionDenied`). |
| `connector token file unusable` or `unavailable` (error, at start) | The token file is missing, unreadable or empty. |
| `no adapter registered for protocol` (warn) | A job names a protocol the connector doesn't have; it is reported so the vault moves on. |
| `rotation refused: built-in Administrator account` (warn) | Expected for RID 500 accounts; nothing was changed. |
| `ssh host key refused` (warn) | The SSH target is unpinned or presented another key. `detail` names the presented fingerprint; pin or re-pin the target. |

## Shutdown

On SIGINT or SIGTERM the worker stops polling and the server stops accepting new calls, waiting up
to 10 seconds for in-flight calls to finish before stopping. A job that was cut short is reclaimed
by the vault after its claim window.

## Panics

A panic in a gRPC handler is recovered: the caller gets a generic `Internal` error, and the panic
value and stack go only to the log (at error level) and to the active trace span.
