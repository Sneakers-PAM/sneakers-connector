# Configuration

The connector reads its settings from environment variables at start. `.env.example` holds safe
local defaults.

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | `localhost:9091` | The vault's gRPC address (`host:port`). The connection has no TLS of its own, so run it where the network or a mesh protects it. |
| `GRPC_PORT` | `9090` | The port the health services listen on. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | unset (no export) | OTLP gRPC collector for traces and metrics, as a URL: `http://collector:4317` for plaintext, `https://collector:4317` for TLS. A bare `host:port` still connects as plaintext, but the OpenTelemetry SDK, which reads this variable too, logs `parse url` errors at start. Any other scheme stops the service at start. Unset or empty disables export cleanly; set it to opt in. |
| `OTLP_LOGS_ENABLED` | unset (off) | `true` exports filtered logs to the same collector. Only JSON log lines are exported, stdout doesn't change, and any other value leaves it off. See [Exported logs](#exported-logs). |
| `OTLP_INSECURE_SKIP_VERIFY` | unset (off) | `true` turns off certificate checks on an `https` collector, for a private certificate. Traces and metrics still flow, but logs stay off, because logs never go to a collector that isn't verified. |
| `WORKLOAD_TOKEN_FILE` | (none) | Path to the workload token, a Kubernetes projected ServiceAccount token with audience `sneakers` (the chart mounts it at `/var/run/secrets/sneakers/token`). Sent on every vault call; see [Vault identity token](#vault-identity-token). When set, it wins over `CONNECTOR_TOKEN_FILE` and `CONNECTOR_DEV_TOKEN`. |
| `CONNECTOR_TOKEN_FILE` | (none) | The older name for `WORKLOAD_TOKEN_FILE`, read only when that is unset. When set, it wins over `CONNECTOR_DEV_TOKEN`. |
| `CONNECTOR_TOKEN_DIR` | `/var/run/secrets/` | The directory the token file must sit under. Must be absolute. Only read when a token file is set. |
| `CONNECTOR_DEV_TOKEN` | `dev-connector-token` | Static dev token, used only when no token file is set. The vault accepts it outside production only. |
| `CONNECTOR_TLS_INSECURE` | (unset) | `true` or `1` skips certificate checks on LDAPS. Only for a test directory with a self-signed certificate; never in production, because the connection carries the new password. |
| `LOG_LEVEL`, `LOG_FORMAT` | `go-log` defaults | Log level and format. Local development uses `trace` and `console`; clusters log JSON. |

These are fixed in code: the poll interval (30 seconds), the batch size (20 heartbeat jobs and 20
rotation jobs per poll), and the per-job time limits (20 seconds for a heartbeat, 30 for a rotation).

## Exported logs

Export is default-deny. A record carries its time, level, service and message, plus only the fields
below. Anything else stays on stdout.

- Exported as they are: `secret_id`, `result`, `error_code`, `error_class`, `backoff`, `pinned_keys`,
  `pinned_certificates`, `builtin_administrator`, `admin_count`, `dependency`, `required`, `from`,
  `to`, `port`.
- Exported as their class only (`[string]`): `error`, `detail`, `reason`. Their text comes from the
  systems the connector acts on and can echo a credential, so use `result` and `error_code` to
  tell failures apart.

`snk_` tokens are redacted from anything exported. The minimum level is info. `protocol` isn't
exported, because a job can carry a name no adapter knows.

## Exported traces and metrics

Export is default-deny too. No baggage comes in or goes out, and SDK errors print only a gRPC code.

- Span names: this service's and the vault's gRPC methods and the gRPC health check. Any other span
  stays in the trace, named `[span]`.
- Span and metric attributes: `rpc.method`, when it's one of the `sneakers.*.v1` methods, and
  `rpc.response.status_code`.
- Resource: `service.name` only, whatever `OTEL_RESOURCE_ATTRIBUTES` says.

Status text and exception events never leave, so a target's error text stays out of traces.

## Vault identity token

Every call to the vault carries the connector's workload identity twice:

- as `authorization: Bearer <token>` gRPC metadata, which the vault's service-to-service check
  verifies before the call runs. Both sides use the owner's helper package
  `github.com/Bugs5382/go-workload-identity` (v1.0.0), which replaced the old private copy. The token file is read again on every
  call, so a token the kubelet rotates is sent without a restart. With no token file set no
  bearer is sent, which only a vault with authentication off (local development) accepts;
- in the request's `identity.token` field (claim, reveal and report, for heartbeats and
  rotations), which the vault's worker-identity verifier checks.

Both come from the file named by `WORKLOAD_TOKEN_FILE`, or `CONNECTOR_TOKEN_FILE` when that is
unset. The field falls back to `CONNECTOR_DEV_TOKEN` when no file is set. The vault side is
described in the vault repository's `docs/workload-auth.md` and `docs/worker-identity.md`.

### Token file path rules

The connector checks the token file path at start and refuses to start, with an error naming the
variable, unless the path:

- is absolute;
- is already in clean form: no `..` or `.` segments, no doubled `//` and no trailing `/`;
- sits under `CONNECTOR_TOKEN_DIR` (a file in a sibling such as `/var/run/secrets-other/` doesn't
  count, and neither does the directory itself).

A projected token mounted at `/var/run/secrets/sneakers/token` passes with no extra settings. If you
mount it outside `/var/run/secrets/`, set `CONNECTOR_TOKEN_DIR` to match. The check is lexical, so
symlinks aren't resolved.

### Token file behaviour

- The file is read at start. A missing, unreadable or empty (whitespace-only) file stops the
  connector with an error naming the path.
- The token is fetched at the start of every poll. The file is re-read when its mtime changes, and
  at least every 60 seconds even if the mtime hasn't moved, so a token the kubelet rotates in place
  is used without a restart.
- If a re-read fails or finds the file empty, the connector keeps the last good token and logs a
  warning. It tries again on the next poll.
- Surrounding whitespace, such as a trailing newline, is trimmed.
- The token value is never logged. Logs carry the path (`token_file`), the file mtime and the
  reload reason (`mtime changed` or `refresh interval`).
