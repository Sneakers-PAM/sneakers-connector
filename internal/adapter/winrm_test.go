// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"strings"
	"testing"
)

func TestWinRMRegistered(t *testing.T) {
	if _, ok := Get("winrm"); !ok {
		t.Fatal(`Get("winrm") ok = false, want true (winrmAdapter should register itself in init)`)
	}
}

func TestWinRMValidateAndRotateNotImplemented(t *testing.T) {
	a, ok := Get("winrm")
	if !ok {
		t.Fatal("winrm adapter not registered")
	}

	result, detail := a.Validate(context.Background(), Conn{}, Cred{})
	if result != Unreachable {
		t.Fatalf("Validate() result = %v, want %v", result, Unreachable)
	}
	if !strings.Contains(detail, "not yet implemented") {
		t.Fatalf("Validate() detail = %q, want it to contain %q", detail, "not yet implemented")
	}

	result, detail = a.Rotate(context.Background(), Conn{}, Cred{}, "new-pw")
	if result != Unreachable {
		t.Fatalf("Rotate() result = %v, want %v", result, Unreachable)
	}
	if !strings.Contains(detail, "not yet implemented") {
		t.Fatalf("Rotate() detail = %q, want it to contain %q", detail, "not yet implemented")
	}
	if !strings.Contains(detail, "winrm") {
		t.Fatalf("Rotate() detail = %q, want it to name the protocol", detail)
	}
}
