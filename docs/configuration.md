# Configuration

The connector reads its settings from environment variables at start. `.env.example` holds safe
local defaults.

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | `localhost:9091` | The vault's gRPC address (`host:port`). The connection has no TLS of its own, so run it where the network or a mesh protects it. |
| `GRPC_PORT` | `9090` | The port the health services listen on. |
| `DATABASE_DSN` | (required) | Not used: the connector has no database. The shared config loader still refuses to start without it, so set any value. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OpenTelemetry OTLP gRPC endpoint for traces and metrics. |
| `CONNECTOR_TOKEN_FILE` | (none) | Path to the worker-identity token file, normally a Kubernetes projected ServiceAccount token. When set, it wins over `CONNECTOR_DEV_TOKEN`. |
| `CONNECTOR_TOKEN_DIR` | `/var/run/secrets/` | The directory the token file must sit under. Must be absolute. Only read when `CONNECTOR_TOKEN_FILE` is set. |
| `CONNECTOR_DEV_TOKEN` | `dev-connector-token` | Static dev token, used only when `CONNECTOR_TOKEN_FILE` is unset. The vault accepts it outside production only. |
| `CONNECTOR_TLS_INSECURE` | (unset) | `true` or `1` skips certificate checks on LDAPS. Only for a test directory with a self-signed certificate; never in production, because the connection carries the new password. |
| `LOG_LEVEL`, `LOG_FORMAT` | `go-log` defaults | Log level and format. Local development uses `trace` and `console`; clusters log JSON. |

These are fixed in code: the poll interval (30 seconds), the batch size (20 heartbeat jobs and 20
rotation jobs per poll), and the per-job time limits (20 seconds for a heartbeat, 30 for a rotation).

## Vault identity token

Every call to the vault's connector API (claim, reveal and report, for heartbeats and rotations)
carries a worker-identity token in the request's `identity.token` field, which the vault's
worker-identity verifier checks. The token comes from `CONNECTOR_TOKEN_FILE`, or from
`CONNECTOR_DEV_TOKEN` when no file is set. The vault side is described in the vault repository's
`docs/worker-identity.md`.

### Token file path rules

The connector checks `CONNECTOR_TOKEN_FILE` at start and refuses to start, with an error naming the
variable, unless the path:

- is absolute;
- is already in clean form: no `..` or `.` segments, no doubled `//` and no trailing `/`;
- sits under `CONNECTOR_TOKEN_DIR` (a file in a sibling such as `/var/run/secrets-other/` doesn't
  count, and neither does the directory itself).

A projected token mounted at `/var/run/secrets/tokens/token` passes with no extra settings. If you
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
