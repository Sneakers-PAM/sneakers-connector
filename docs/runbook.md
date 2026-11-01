# Runbook

## Start up

At start the connector:

1. reads its configuration from the environment (`DATABASE_DSN` must be set, though nothing uses
   it);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. sets up the client for the vault at `VAULT_ADDR`, sending the workload token on every call (the
   connection is made lazily, on the first call; an unreadable token file fails here);
4. loads the worker token: the file at `WORKLOAD_TOKEN_FILE` (or `CONNECTOR_TOKEN_FILE`), or the
   dev token;
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

That's readiness: it answers `NOT_SERVING` while the vault is down. Liveness is service
`liveness` (`grpcurl -plaintext -d '{"service":"liveness"}' localhost:9090 grpc.health.v1.Health/Check`)
and only says the process is up.

| Dependency | Required | Why |
|---|---|---|
| vault | yes | Every job the worker runs is claimed from the vault and reported back to it; without the vault the connector does nothing. Checked through the vault's own readiness on the worker's connection. |
| otlp | no | The OpenTelemetry collector, listed only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. It's down when the last export error on traces or metrics, or on logs when they're on, is newer than the last success. That shows as degraded and never fails readiness. Failed exports print a gRPC code to stderr at most once every 30 seconds, with no endpoint or headers. |

There's no database dependency: `DATABASE_DSN` is read but nothing uses it, and the connector uses
no message broker. A vault that is up but itself not ready (its database down) also makes the
connector not ready, since neither can work until it's back. Readiness answers carry the
`sneakers-health` header with each dependency's state (see [api.md](api.md)); each change of state
logs one line, `dependency check failing` (warn) or `dependency recovered` (info), with the
dependency's name, the states it moved between and the error class, never the address or the
error text.

Readiness doesn't check that the vault accepts the worker's token; the warnings in the log do
(`claim due heartbeats`, `claim due rotations`).

The kubelet's liveness probe has to ask for service `liveness`; that's set in the sneakers-release
chart. Until it does, both probes ask readiness, and a vault outage would restart the pod.

To see which build is running, ask for the response headers (`grpcurl -v ... grpc.health.v1.Health/Check`):
the answer carries `sneakers-version` and `sneakers-commit`. The image build stamps them from its
`VERSION` and `COMMIT` build arguments, into go-buildinfo's `Version` and `Commit`:

```bash
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

## Each poll

A poll runs the due heartbeats, then the due rotations, one job at a time. Each job has its own
time limit (20 seconds for a heartbeat, 30 for a rotation), so one slow target can't hold up the
rest of the batch. A failure on one job is logged with its `secret_id` and never stops the others.
A heartbeat target of any protocol that can't be reached is backed off, 5 minutes doubling up to an
hour, before the connector contacts it again (see "TLS to targets" for the SSH rules).

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

LDAPS checks the target's certificate against the system roots, unless the target has TLS
certificate pins. `CONNECTOR_TLS_INSECURE=true` turns the check off for a test directory only; it
is a dev seam, never a setting, and pinning never turns the check off.

A pin is the SHA-256 fingerprint of a certificate, as 64 hex digits (an optional `sha256:` prefix,
colons between bytes and any case are accepted). With at least one usable pin, the connector trusts
the target's certificate only when:

- the certificate is within its validity dates and covers the target's host name, as without a
  pin, and
- its own fingerprint is pinned (a leaf pin), or a pinned CA certificate that the server sends in
  its chain signs it (a CA pin). A CA pin keeps working when the server's certificate is renewed by
  the same CA; a leaf pin must be pinned again.

A chain that matches no pin fails before the credential is sent. The detail names the presented
fingerprints (the server's certificate first) and the pinned ones, so the old and new certificate
can be compared before re-pinning. A target with no usable pin keeps using the system roots, so a
publicly issued certificate needs no pin. The vault doesn't send TLS pins with jobs yet; until it
does, every LDAPS target uses the system roots.

A certificate that fails the check any other way than a pin mismatch is reported as an untrusted
certificate, never as unreachable: the target answered, and the credential was never sent. The
detail starts with `untrusted certificate:` and names the first thing wrong, checked in this order:

| Cause | Detail |
|---|---|
| expired | `the certificate for <name> expired on <date>` |
| not valid yet | `the certificate for <name> isn't valid until <date>` |
| issued for another host name | `the certificate is for <names>, not <host>` |
| the issuer isn't trusted | `the certificate for <name> is signed by <issuer>, which isn't in the trusted CA list` |

The issuer named is the issuer of the last certificate the server sent, so a server that sends only
its own certificate names its issuing CA. Unreachable stays for a target that can't be reached:
DNS, a refused connection, or a timeout. The heartbeat isn't backed off for an untrusted
certificate; it's checked again on its schedule.

SSH heartbeats connect only to a host that presents one of the target's pinned host keys, the same
check the SSH broker makes. The vault sends the pins with each job. A heartbeat signs in as the
account, with the secret's private key, or with its password when the secret has no key (offered as
`password` and `keyboard-interactive`), and closes the connection once the sign-in completes. It
runs no command. The host key is checked during key exchange, before any credential is offered, so
a host that isn't verified never sees it.

A heartbeat never opens a connection it means to drop before authenticating. OpenSSH 9.8 and later
penalise those under `PerSourcePenalties` ("connections without attempting authentication"), and
the penalties escalate until the Sneakers address is refused, which breaks real sessions and
rotation as well.

- **Not pinned.** A target with no pins (or none that parse) is never contacted, and the
  credential isn't revealed. The heartbeat reports `HOST_KEY_NOT_PINNED` with "host key not pinned
  for this target: pin the host key first; no connection was made".
- **Mismatch.** A host whose key matches none of the pins costs one connection, refused during key
  exchange. The heartbeat reports `HOST_KEY_MISMATCH` with the presented and the pinned SHA256
  fingerprints, `host key mismatch (presented SHA256:..., pinned SHA256:..., SHA256:...)`, and then
  stops contacting that target. Later heartbeats are reported `HOST_KEY_MISMATCH` without a
  connection, their detail ending "heartbeat stopped for this target until its host key is
  re-pinned". Re-pinning the target (or moving it) makes the next heartbeat try again.
- **Unreachable.** A target that can't be reached isn't contacted again for 5 minutes, then 10,
  20 and so on, capped at an hour, however often the vault hands out its heartbeat (the vault backs
  off `UNREACHABLE` on its side too). Heartbeats in between are reported `UNREACHABLE` without a
  connection, with "backing off after N failed attempts, next attempt after <time>". A good result
  clears it.

The connector keeps the stopped and backing-off targets in memory, keyed by protocol, address and
pins, so a restarted connector tries each of them once more, and each connector replica keeps its
own.

Neither host-key result is a wrong credential: the connector reports them as their own heartbeat
results (`HOST_KEY_NOT_PINNED`, `HOST_KEY_MISMATCH`), never as `FAILED`. The vault records them as a
failed check, notifies the first one like a drift and audits each as `secret.heartbeat.host_key`
with the detail, so an admin sees the fingerprints and can re-pin or investigate. No detail or log
carries key material. Pin the target in the vault (site admins only) with the key's authorized_keys
line.

The only other connection to a target that stops at the host key is the SSH broker's
`ScanHostKey`, which the pin dialog calls on demand: one connection per scan, never on a schedule.

## Troubleshooting

| Log message | Meaning |
|---|---|
| `claim due heartbeats` or `claim due rotations` (warn) | The vault is unreachable, or refused the token. The error says which (`Unavailable`, `PermissionDenied`). |
| `connector token file unusable` or `unavailable` (error, at start) | The token file is missing, unreadable or empty. |
| `no adapter registered for protocol` (warn) | A job names a protocol the connector doesn't have; it is reported so the vault moves on. |
| `rotation refused: built-in Administrator account` (warn) | Expected for RID 500 accounts; nothing was changed. |
| `heartbeat refused before contacting the target` (warn) | The SSH target has no usable pin, so nothing was sent to it. Pin the target. |
| `ssh host key refused` (warn) | The SSH target presented a key matching none of its pins. `detail` names the presented and pinned fingerprints; re-pin the target or investigate. |
| `heartbeat stopped for this target until its host key is re-pinned` (warn) | Follows a mismatch: later heartbeats of that target are reported without a connection. |
| `target certificate not trusted; the credential was not sent` (warn) | The LDAPS target's certificate failed the check. `detail` says why (see "TLS to targets"). |
| `rotation stopped: target certificate not trusted; nothing changed` (warn) | The same, on a rotation: the password wasn't changed. |
| `tls certificate matches none of the target's pins; the credential was not sent` (warn) | The TLS target presented a certificate that isn't pinned and isn't signed by a pinned CA. `detail` names the presented and pinned fingerprints; re-pin the target or investigate. |
| `rotation stopped: tls certificate matches none of the target's pins; nothing changed` (warn) | The same, on a rotation: the password wasn't changed. |
| `target unreachable; backing off` (warn) | The target couldn't be reached; `backoff` says how long until it is tried again. |
| `heartbeat held: target not contacted` (info) | A heartbeat of a stopped or backing-off target, reported without a connection. |

## Shutdown

On SIGINT or SIGTERM the worker stops polling and the server stops accepting new calls, waiting up
to 10 seconds for in-flight calls to finish before stopping. A job that was cut short is reclaimed
by the vault after its claim window.

## Panics

A panic in a gRPC handler is recovered: the caller gets a generic `Internal` error, and the panic
value and stack go only to the log (at error level) and to the active trace span.
