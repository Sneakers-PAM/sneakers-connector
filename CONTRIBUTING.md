# Contributing to sneakers-connector

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). `go test ./...` needs nothing else running; the LDAP
  adapter's live tests also run when an lldap container listens on localhost:23890 with base DN
  `dc=example,dc=org`, and skip otherwise.
- Adding a target protocol: write an adapter in `internal/adapter` and register it there; the
  worker doesn't change. Every job must end in a report to the vault, and credential material is
  never logged.
- Changing the health API: edit `proto/sneakers/common/v1/health.proto`, then run `buf generate`
  (with the `protoc-gen-go` and `protoc-gen-go-grpc` versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`) and commit the result under `gen/go`. CI fails if the
  generated code is stale or the change breaks the API.
- Every `.go` and `.proto` file starts with the Apache-2.0 header:

  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- No real names, hosts, addresses, domains, DNs, accounts or other identifiers in code, tests,
  fixtures or docs. Use example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
