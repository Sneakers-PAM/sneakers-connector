// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"strings"
	"testing"
)

func TestSAMRRegistered(t *testing.T) {
	if _, ok := Get("samr"); !ok {
		t.Fatal(`Get("samr") ok = false, want true (samrAdapter should register itself in init)`)
	}
}

func TestSAMRValidateAndRotateNotImplemented(t *testing.T) {
	a, ok := Get("samr")
	if !ok {
		t.Fatal("samr adapter not registered")
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
	if !strings.Contains(detail, "samr") {
		t.Fatalf("Rotate() detail = %q, want it to name the protocol", detail)
	}
}
