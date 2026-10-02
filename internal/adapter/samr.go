// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import "context"

// samrAdapter is a placeholder registration for the "samr" protocol
// (Windows local/domain account management over MS-SAMR). The target
// protocol list names SAMR so it's discoverable in the registry, but
// its Validate/Rotate behavior is deferred: neither is implemented yet.
type samrAdapter struct{}

func init() {
	Register("samr", &samrAdapter{})
}

// Validate always reports Unreachable: neither SAMR operation is
// implemented yet (see Rotate).
func (a *samrAdapter) Validate(_ context.Context, _ Conn, _ Cred) (Result, string) {
	return Unreachable, "rotation via samr not yet implemented"
}

// Rotate always reports Unreachable: SAMR rotation isn't implemented.
func (a *samrAdapter) Rotate(_ context.Context, _ Conn, _ Cred, _ string) (Result, string) {
	return Unreachable, "rotation via samr not yet implemented"
}
