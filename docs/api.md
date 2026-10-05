# API

The connector has no API of its own for other services to drive. It is a client of the vault, and
it serves only health checks.

## What it serves

On `GRPC_PORT`:

- `grpc.health.v1.Health`: the standard gRPC health service, for probes:
  - service `""` is readiness. It answers `NOT_SERVING` while a required dependency is down and
    `SERVING` otherwise, and recovers on its own when the dependency answers again.
  - service `liveness` always answers `SERVING` and checks no dependency, so an outage never
    restarts the pod.
  - any other service answers `NOT_FOUND`; `Watch` answers `UNIMPLEMENTED` (poll `Check`).
- `sneakers.common.v1.HealthService/Check`: answers `status: "SERVING"`. Defined in
  [proto/sneakers/common/v1/health.proto](../proto/sneakers/common/v1/health.proto).
- gRPC server reflection.

A `grpc.health.v1.Health/Check` answer carries the build in its response headers: `sneakers-version` (the image
tag, `dev` when unstamped) and `sneakers-commit` (the source commit, `unknown` when neither the
build nor Go's VCS stamp knows it). The gateway's diagnostics read them.

A readiness answer (service `""`) also carries `sneakers-health`, the dependency report as compact
JSON:

```json
{"status":"down","dependencies":[{"name":"vault","state":"down","required":true,"error":"unavailable","checkedAt":"2026-10-05T12:00:05Z"}]}
```

`status` and each `state` are `ok`, `degraded` (an optional dependency is failing) or `down` (a
required one is). `error` is a fixed class, never the error itself: `timeout`, `refused`,
`unavailable`, `unauthenticated` or `error`. Each dependency is checked with a one-second timeout,
and the result answers for five seconds, so frequent probes don't load the vault.

`sneakers.common.v1.HealthService/Check` is unchanged and always answers `SERVING`.

## What it calls on the vault

All six calls are on `sneakers.vault.v1.VaultService` (the stubs are generated here, see
[Calling other services](#calling-other-services)). Each carries the workload token as
`authorization: Bearer <token>` metadata and the worker-identity token in `identity.token` (see
[configuration.md](configuration.md#vault-identity-token)). Each also carries the connector's
build as metadata: `sneakers-version` (the stamped version, `dev` when unstamped) and
`sneakers-commit` (the stamped commit, else the VCS revision, else `unknown`). The vault records
them with the connector's last contact, so the product's diagnostics show every connector's build
without calling the connector.

| Call | When | What the connector does with it |
|---|---|---|
| `ClaimDueHeartbeats` | every poll, limit 20 | one heartbeat per job |
| `RevealForHeartbeat` | per heartbeat job | gets the username and the password, or the private key and passphrase |
| `ReportHeartbeat` | per heartbeat job | sends the result, a detail message and, when it read them, the account flags |
| `ClaimDueRotations` | every poll, after the heartbeats, limit 20 | one rotation per job |
| `RevealForRotation` | per rotation job | gets the username, the current password, the new password the vault generated and the staged version |
| `ReportRotation` | per rotation job | sends the change and validate phases, a detail message, the staged version and, for a refusal, the built-in Administrator flag |

A job whose protocol has no adapter, or which has no connection, is still reported (heartbeat
`UNREACHABLE`, rotation `SKIPPED` for both phases), so the vault moves its schedule on rather than
handing the same job out again on every poll. A failed reveal is logged and the job is left for a
later poll, with no report.

## Calling other services

The connector never imports another service's Go module. It generates its own client stubs from
the callee's protos, pinned by commit:

- `proto-refs.env` pins each callee: `SNEAKERS_VAULT_REF=<commit>` for `Sneakers-PAM/sneakers-vault`.
- `scripts/proto-generate.sh` downloads only the callee's `proto/` at that commit into `.protos/`
  (git-ignored) and runs `buf generate`. The stubs land in `gen/go/thirdparty/vault/v1`, a Go
  package of this module, so they can't collide with the vault's own. The stubs are committed, so
  a build needs no network; the protos never are.
- To try an unmerged vault proto change, point `SNEAKERS_VAULT_PROTO_DIR` at a local `proto/`
  directory and run the script.
- To move to a newer vault, change the ref, run the script and commit `proto-refs.env` and `gen/`
  together. Build & Test fails when `gen/` doesn't match the pins.
- The same ref pins `internal/workloadauth`, the service-to-service authentication package copied
  byte for byte from the vault. `scripts/workloadauth-check.sh` downloads the vault's copy at the ref
  and fails Build & Test when this one differs (`SNEAKERS_VAULT_DIR` points it at a local vault
  checkout instead).
- The `proto-sync` check (from `Sneakers-PAM/.github`) fails a PR whose pin isn't on the vault's
  `main` or that the vault's `main` breaks, and warns when `main` has moved on. On a schedule it
  opens a PR that bumps the pin.

## Adapters

The job's `connection.protocol` picks the adapter. Its connection and target fields map onto what
the adapter is given:

| Job field | Adapter field |
|---|---|
| `connection.host`, `connection.port` | host and port |
| `connection.use_tls` | TLS on (LDAPS) |
| `target.domain` | domain |
| `target.realm` | Kerberos realm |
| `target.ssh_host_keys` | the SSH host-key pins (authorized_keys lines); empty means not pinned |

| Protocol | Heartbeat | Rotation |
|---|---|---|
| `ldap`, `ldaps` | binds as the account | changes the account's own password |
| `kerberos` | requests a ticket (AS-REQ) for the account | changes the password over kpasswd (RFC 3244), on port 464 of the same host |
| `ssh` | public-key handshake as the account, only to a host presenting a pinned host key; no command is run | not supported (reports unreachable) |
| `winrm`, `samr` | placeholder: reports unreachable | placeholder: reports unreachable |

### LDAP and the domain field

`target.domain` decides how the LDAP adapter binds and changes the password:

- empty: binds with the username as given (a full DN, or a name the target accepts);
- a DN, such as `dc=example,dc=org`: an lldap-style directory. Binds as
  `uid=<username>,ou=people,<domain>` and changes the password with the RFC 3062 Password Modify
  operation;
- a DNS domain, such as `ad.example.org`: Active Directory. Binds as `<username>@<domain>`, finds
  the account by `sAMAccountName` under the matching base (`dc=ad,dc=example,dc=org`), and changes
  the password with AD's self-service change: one modify that deletes the old `unicodePwd` and adds
  the new one. AD only allows that over an encrypted connection, so use LDAPS.

After a successful AD bind, a heartbeat also reads `objectSid` and `adminCount` and reports
`builtin_administrator` (the RID is 500) and `admin_count` (`adminCount` is 1), so the vault knows
both before the first rotation. If the lookup fails, the heartbeat result stands and no flags are
sent.

### Kerberos realm

The realm is `target.realm`, or `target.domain` when no realm is set, upper-cased. With neither,
the Kerberos adapter reports unreachable. The KDC is `connection.host` on `connection.port`, or 88
when the port is 0.

## Results

| Adapter outcome | Heartbeat result | Rotation phase |
|---|---|---|
| valid | `OK` | `OK` |
| invalid (the target rejected the credential or the change) | `FAILED` | `FAILED` |
| unreachable (no answer, or an answer that doesn't confirm a rejection) | `UNREACHABLE` | `FAILED` |
| SSH target with no usable pin; the account's key is never offered | `HOST_KEY_NOT_PINNED` | `FAILED` |
| SSH host presented a key matching none of the pins; the account's key is never offered | `HOST_KEY_MISMATCH` | `FAILED` |
| refused (the built-in Administrator) | not used | `SKIPPED` for both, with `builtin_administrator` set |

A rotation reports two phases. **Change** is the outcome of changing the password. **Validate** is
the outcome of signing in with the new password, and runs only when the change succeeded;
otherwise it is `SKIPPED` and the vault keeps the old credential. When the target has a realm, the
new password is validated over Kerberos (on port 88) whatever protocol made the change, because an
AD LDAP bind may still accept the old password for a while after a change.
