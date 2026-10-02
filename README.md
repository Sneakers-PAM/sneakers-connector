# Connector Service 🔌

> 🔁 The Sneakers-PAM connector: it tests and rotates stored credentials on the systems they belong to, with no agent on those systems.

The connector is a worker. Every 30 seconds it asks the vault for the heartbeat and rotation jobs
that are due, reveals each credential through the vault's connector API, and acts on the target
over a standard protocol: it signs in to prove a credential still works, or changes the password
and then proves the new one works. It reports every outcome back to the vault, which keeps the
schedule, the secret versions and the audit trail. Nothing is installed on the targets.

## ✨ Highlights

- 🧩 **Adapters:** LDAP and LDAPS (Active Directory and lldap), Kerberos and SSH, picked by the job's protocol; WinRM and SAMR are registered placeholders that report unreachable.
- 🔐 **Self-service rotation:** the account changes its own password with its current one, so the connector needs no admin rights on the directory.
- 🛡️ **Built-in Administrator guard:** the domain's RID 500 account is matched by objectSid, never by name, and is never rotated.
- ✅ **Proven changes:** after an AD change, the new password is checked over Kerberos, which stops accepting the old one at once.
- 🤐 **No secrets in logs:** credentials and the worker token are never logged.

## 🚀 Run it

The connector needs a vault to pull jobs from. Against a vault on its default local port, with the
dev worker token (the vault accepts it outside production only):

```bash
DATABASE_DSN=unused VAULT_ADDR=localhost:9091 go run ./cmd/connector
```

It serves the gRPC health services on port 9090. It doesn't use a database; `DATABASE_DSN` only has
to be set (see [docs/configuration.md](docs/configuration.md)).

Run the tests. The LDAP adapter's live tests also run when an lldap container listens on
localhost:23890 with base DN `dc=example,dc=org`; without one they skip:

```bash
go test ./...
```

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables and the worker token.
- [docs/api.md](docs/api.md): what it serves, the vault calls it makes (and how its stubs are
  generated), and the adapters.
- [docs/runbook.md](docs/runbook.md): operating the connector.

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
