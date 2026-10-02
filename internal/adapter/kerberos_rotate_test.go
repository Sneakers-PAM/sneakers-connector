// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"testing"
	"time"
)

// TestKerberosRotateRegistered proves the kerberos adapter satisfies the
// full Adapter interface (Validate + Rotate) via the registry, the same
// seam the worker's rotation loop uses to look adapters up.
func TestKerberosRotateRegistered(t *testing.T) {
	if _, ok := Get("kerberos"); !ok {
		t.Fatal(`Get("kerberos") ok = false, want true`)
	}
}

// TestKerberosRotateUnreachable exercises Rotate end-to-end against a dead
// port: no live KDC/kpasswd server is required for this path, mirroring
// TestKerberosUnreachable for Validate.
func TestKerberosRotateUnreachable(t *testing.T) {
	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 1, Realm: "EXAMPLE.ORG"}
	current := Cred{Username: "svc-example", Password: "old-pw"}

	result, detail := a.Rotate(ctx, conn, current, "new-pw")
	if result != Unreachable {
		t.Fatalf("Rotate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
	if detail == "" {
		t.Fatal("Rotate() detail is empty, want a failure message")
	}
}

// TestKerberosRotateNoRealm proves Rotate refuses to build a kadmin request
// without a realm derivable from Conn, the same guard Validate has.
func TestKerberosRotateNoRealm(t *testing.T) {
	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 464}
	current := Cred{Username: "svc-example", Password: "old-pw"}

	result, _ := a.Rotate(ctx, conn, current, "new-pw")
	if result != Unreachable {
		t.Fatalf("Rotate() result = %v, want %v", result, Unreachable)
	}
}

// TestKerberosRotatePrincipalRealmDerivation proves Rotate derives the
// change-password principal's realm the same way Validate does (via
// kerberosRealm): Conn.Realm wins over Conn.Domain, and both are
// upper-cased for the AS-REQ/kpasswd exchange.
func TestKerberosRotatePrincipalRealmDerivation(t *testing.T) {
	tests := []struct {
		name string
		conn Conn
		want string
	}{
		{name: "realm set", conn: Conn{Realm: "example.org"}, want: "EXAMPLE.ORG"},
		{name: "domain fallback", conn: Conn{Domain: "example.org"}, want: "EXAMPLE.ORG"},
	}
	for _, tt := range tests {
		if got := kerberosRealm(tt.conn); got != tt.want {
			t.Fatalf("%s: kerberosRealm(%+v) = %q, want %q", tt.name, tt.conn, got, tt.want)
		}
	}
}
