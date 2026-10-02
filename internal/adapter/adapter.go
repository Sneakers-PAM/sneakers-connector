// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package adapter defines the pluggable protocol adapter seam used by the
// connector worker: one Adapter implementation per target protocol
// (LDAPS, Kerberos, ...). Adding a new target type means adding a new
// adapter and registering it here; the worker/queue code never changes.
package adapter

import (
	"context"
	"sync"
)

// Result is the outcome of validating a credential against a target.
type Result int

const (
	// Valid means the credential successfully authenticated against the target.
	Valid Result = iota
	// Invalid means the target was reachable and rejected the credential.
	Invalid
	// Unreachable means the target could not be contacted to attempt validation.
	Unreachable
	// Refused means the account must never be rotated (the domain's built-in
	// Administrator), so Rotate made no change. Only Rotate returns it.
	Refused
	// HostKeyNotPinned means the target has no pinned host key, so the
	// adapter refused to authenticate to it. Nothing about the credential
	// was learned.
	HostKeyNotPinned
	// HostKeyMismatch means the target presented a host key that matches
	// none of its pins, so the adapter refused to authenticate to it.
	// Nothing about the credential was learned.
	HostKeyMismatch
)

// BuiltinAdministratorReason is the detail Rotate reports with Refused.
const BuiltinAdministratorReason = "built-in Administrator account (RID 500), rotation is not allowed"

// String returns the lower-case name of the Result.
func (r Result) String() string {
	switch r {
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	case Unreachable:
		return "unreachable"
	case Refused:
		return "refused"
	case HostKeyNotPinned:
		return "host_key_not_pinned"
	case HostKeyMismatch:
		return "host_key_mismatch"
	default:
		return "unknown"
	}
}

// Cred is the credential being validated. Password is used by password-based
// adapters (winrm/kerberos/ldap); PrivateKey/Passphrase are used by key-based
// adapters (ssh). Only the fields relevant to a protocol are populated.
type Cred struct {
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

// Conn describes how to reach the target for a validation attempt.
type Conn struct {
	Host   string
	Port   int
	UseTLS bool
	Domain string
	Realm  string
	// HostKeys are the target's pinned SSH host keys in authorized_keys
	// form. The ssh adapter connects only to a host presenting one of them;
	// empty means not pinned, and it refuses to connect.
	HostKeys []string
}

// Adapter validates a credential against a target by binding as the account,
// and can change that account's own password on the target (rotation).
type Adapter interface {
	// Validate attempts to authenticate cred against the target described by c,
	// returning the outcome and a human-readable detail (e.g. an error message).
	Validate(ctx context.Context, c Conn, cred Cred) (Result, string)

	// Rotate changes the account's own password on the target described by c,
	// authenticating as the account with current and setting newPassword.
	// It returns Valid when the change succeeds, Invalid when the target
	// authoritatively rejects current or newPassword (e.g. bad current
	// credential, password-policy/constraint violation), and Unreachable
	// when the outcome could not be determined (dial failure, timeout, or
	// any other error that doesn't confirm a rejection). Rotate never logs
	// current or newPassword.
	Rotate(ctx context.Context, c Conn, current Cred, newPassword string) (Result, string)
}

// AccountFlags is what an adapter read about an AD account. Known is false
// when it could not tell, and the other fields are then meaningless.
type AccountFlags struct {
	Known bool
	// BuiltinAdministrator: the objectSid RID is 500.
	BuiltinAdministrator bool
	// AdminCount: adminCount is 1 (a protected-group member). Such accounts
	// rotate only with the self-service change, because OU delegation does
	// not apply to them.
	AdminCount bool
}

// AccountValidator is an Adapter that also reports AccountFlags while
// validating, so the vault learns them before the first rotation attempt.
type AccountValidator interface {
	ValidateAccount(ctx context.Context, c Conn, cred Cred) (Result, string, AccountFlags)
}

var (
	mu       sync.RWMutex
	adapters = map[string]Adapter{}
)

// Register adds an Adapter to the registry under protocol (e.g. "ldaps",
// "kerberos"). Adapter packages call this from an init() or an explicit
// New() so they can plug into the registry without the registry package
// depending on them.
func Register(protocol string, a Adapter) {
	mu.Lock()
	defer mu.Unlock()
	adapters[protocol] = a
}

// Get looks up the Adapter registered for protocol.
func Get(protocol string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := adapters[protocol]
	return a, ok
}

// Registry returns a snapshot of all registered adapters keyed by protocol.
func Registry() map[string]Adapter {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]Adapter, len(adapters))
	for k, v := range adapters {
		out[k] = v
	}
	return out
}
