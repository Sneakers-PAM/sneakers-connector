// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import "context"

// winrmAdapter is a placeholder registration for the "winrm" protocol
// (Windows Remote Management). The target protocol list
// names WinRM so it's discoverable in the registry, but its Validate/Rotate
// behavior is deferred: neither is implemented yet.
type winrmAdapter struct{}

func init() {
	Register("winrm", &winrmAdapter{})
}

// Validate always reports Unreachable: neither WinRM operation is
// implemented yet (see Rotate).
func (a *winrmAdapter) Validate(_ context.Context, _ Conn, _ Cred) (Result, string) {
	return Unreachable, "rotation via winrm not yet implemented"
}

// Rotate always reports Unreachable: WinRM rotation isn't implemented.
func (a *winrmAdapter) Rotate(_ context.Context, _ Conn, _ Cred, _ string) (Result, string) {
	return Unreachable, "rotation via winrm not yet implemented"
}
