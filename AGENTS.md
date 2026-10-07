# AGENTS.md - sneakers-connector

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers connector: the agentless worker that tests and rotates stored credentials on their target
systems. It polls the vault's connector API for due heartbeat and rotation jobs, reveals each
credential, acts on the target through a protocol adapter (LDAP/LDAPS, Kerberos, SSH), and reports
the outcome back. It serves only the health services. Before changing it, know that every job must
end in a report (a skipped job is reported, not dropped, or the vault hands it out forever), that
it never rotates the domain's built-in Administrator (RID 500, matched by `objectSid`), and that it
never logs credential material or the worker token.

## Layout

- `cmd/connector/` - the entrypoint: config, OpenTelemetry, the vault client, the token source,
  the worker and the gRPC server.
- `internal/adapter/` - the protocol adapter registry and the LDAP, Kerberos, SSH, WinRM and SAMR
  adapters, with their tests.
- `internal/worker/` - the heartbeat and rotation poll loops and their tests (against a fake vault
  client).
- `internal/tokensource/` - the worker-identity token: a projected token file or the dev token.
- `internal/vaultclient/` - the gRPC client for the vault; it sends the workload token on every call.
- Service-to-service authentication (the token sent to the vault) comes from
  `github.com/Bugs5382/go-workload-identity`.
- `internal/grpcsvc/` - the `sneakers.common.v1.HealthService` handler.
- `internal/config/`, `internal/server/` - the environment config and the gRPC server bootstrap,
  with the health service and readiness checks from `github.com/Bugs5382/go-buildinfo`.
- `proto/` - the health API; `gen/go/` - the generated Go (committed, checked current in CI),
  including the vault client stubs in `gen/go/thirdparty/vault/v1`, generated from the vault
  protos pinned in `proto-refs.env` (see docs/api.md, "Calling other services").
- `docs/` - configuration, API and runbook.

## Build, test, lint

- Build: `task build`
- Test: `task test`. Everything runs against in-process fakes and loopback listeners, except the
  LDAP adapter's live tests, which need lldap on localhost:23890 with base DN `dc=example,dc=org`
  (they skip without it; CI runs one), and the Kerberos live tests, which need a KDC and the
  `KRB_TEST_*` variables (they skip without them).
- Lint: `task lint`, plus `buf lint` for the proto (after `scripts/proto-generate.sh` has fetched
  the vault protos).
- Generated code: `scripts/proto-generate.sh`, with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`.
- Vulnerabilities: `task vuln` runs govulncheck as CI does (`scripts/govulncheck.sh`): any called
  finding fails unless its ID is in `govulncheck-allow.txt`, which says why and when each entry
  goes. `scripts/govulncheck_test.sh` checks the filter itself.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names, domains, DNs and accounts.
- The vault API comes from `github.com/Sneakers-PAM/sneakers-vault` (`gen/go/sneakers/vault/v1`).
- Adding a target protocol means a new adapter registered in `internal/adapter`; the worker doesn't
  change.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`. For local callee protos,
  point `SNEAKERS_VAULT_PROTO_DIR` at a local `proto/` directory when running
  `scripts/proto-generate.sh`, rather than editing a pin in `proto-refs.env`.
