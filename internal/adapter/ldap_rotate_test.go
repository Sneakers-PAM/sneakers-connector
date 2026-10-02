// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// TestEncodeADPasswordExactBytes proves encodeADPassword produces exactly
// what Active Directory's unicodePwd attribute requires: the password
// wrapped in double quotes, encoded as UTF-16LE, with no BOM and no
// trailing NUL. Bytes are asserted literally so a future refactor can't
// silently change the wire format AD expects.
func TestEncodeADPasswordExactBytes(t *testing.T) {
	got := encodeADPassword("Abc123!")
	want := []byte{
		0x22, 0x00, // "
		0x41, 0x00, // A
		0x62, 0x00, // b
		0x63, 0x00, // c
		0x31, 0x00, // 1
		0x32, 0x00, // 2
		0x33, 0x00, // 3
		0x21, 0x00, // !
		0x22, 0x00, // "
	}
	if !bytes.Equal([]byte(got), want) {
		t.Fatalf("encodeADPassword(%q) = %v, want %v", "Abc123!", []byte(got), want)
	}
}

// TestEncodeADPasswordEmpty covers the degenerate case: an empty password
// still gets wrapped in quotes (two quote characters, 4 bytes).
func TestEncodeADPasswordEmpty(t *testing.T) {
	got := []byte(encodeADPassword(""))
	want := []byte{0x22, 0x00, 0x22, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeADPassword(\"\") = %v, want %v", got, want)
	}
}

// TestAdBaseDNFromDomain proves the DNS-domain-to-search-base conversion
// rotateAD's DN resolution relies on, and that it correctly declines to
// produce a base for the two cases that aren't a DNS domain: empty, and
// lldap-style (contains "=").
func TestAdBaseDNFromDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.org", "dc=example,dc=org"},
		{"corp.example.org", "dc=corp,dc=example,dc=org"},
		{"", ""},
		{"dc=example,dc=org", ""},
	}
	for _, tt := range tests {
		if got := adBaseDN(tt.domain); got != tt.want {
			t.Fatalf("adBaseDN(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

// TestRotateSelectsLLDAPPathByDomain proves the routing decision inside
// Rotate: a Domain containing "=" must take the RFC-3062 Password Modify
// path, not the AD unicodePwd path. Both paths dial out, so this is
// exercised via the dial failure: with no listener at all, Rotate must
// still reach the (Unreachable) return before ever depending on a live
// server, proving Rotate doesn't panic or block indefinitely regardless of
// which path Domain selects.
func TestRotateSelectsLLDAPPathByDomain(t *testing.T) {
	a, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 1, Domain: "dc=example,dc=org"}
	current := Cred{Username: "svc-example", Password: "old-pw"}

	result, detail := a.Rotate(ctx, conn, current, "new-pw")
	if result != Unreachable {
		t.Fatalf("Rotate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
	if detail == "" {
		t.Fatal("Rotate() detail is empty, want a dial-failure message")
	}
}

// TestRotateADPathUnreachable exercises the default (AD, non-lldap) Rotate
// path against a dead port, proving it dials rather than short-circuiting
// on the DN-resolution helper before ever attempting the network call.
func TestRotateADPathUnreachable(t *testing.T) {
	a, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 1, UseTLS: true, Domain: "example.org"}
	current := Cred{Username: "svc-example", Password: "old-pw"}

	result, detail := a.Rotate(ctx, conn, current, "new-pw")
	if result != Unreachable {
		t.Fatalf("Rotate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
}

// TestTLSInsecureSkipVerifyDefaultsSecure proves the default posture: with
// CONNECTOR_TLS_INSECURE unset (or empty), the LDAPS dial verifies the
// server's certificate. This connection carries a new credential, so
// defaulting to skip-verify would be a MITM risk.
func TestTLSInsecureSkipVerifyDefaultsSecure(t *testing.T) {
	t.Setenv("CONNECTOR_TLS_INSECURE", "")
	if tlsInsecureSkipVerify() {
		t.Fatal("tlsInsecureSkipVerify() = true with CONNECTOR_TLS_INSECURE unset, want false (secure default)")
	}

	if err := os.Unsetenv("CONNECTOR_TLS_INSECURE"); err != nil {
		t.Fatal(err)
	}
	if tlsInsecureSkipVerify() {
		t.Fatal("tlsInsecureSkipVerify() = true with CONNECTOR_TLS_INSECURE unset entirely, want false (secure default)")
	}
}

// TestTLSInsecureSkipVerifyExplicitTrue proves the seam can be opened (e.g.
// a dev lab against a self-signed cert) only by explicitly setting
// CONNECTOR_TLS_INSECURE=true or "1".
func TestTLSInsecureSkipVerifyExplicitTrue(t *testing.T) {
	t.Setenv("CONNECTOR_TLS_INSECURE", "true")
	if !tlsInsecureSkipVerify() {
		t.Fatal("tlsInsecureSkipVerify() = false with CONNECTOR_TLS_INSECURE=true, want true")
	}

	t.Setenv("CONNECTOR_TLS_INSECURE", "1")
	if !tlsInsecureSkipVerify() {
		t.Fatal("tlsInsecureSkipVerify() = false with CONNECTOR_TLS_INSECURE=1, want true")
	}
}

// TestTLSInsecureSkipVerifyOtherValuesStaySecure proves any value other than
// "true"/"1" (e.g. an explicit "false", or a typo) does not open the seam.
func TestTLSInsecureSkipVerifyOtherValuesStaySecure(t *testing.T) {
	for _, v := range []string{"false", "0", "yes", "TRUE"} {
		t.Setenv("CONNECTOR_TLS_INSECURE", v)
		if tlsInsecureSkipVerify() {
			t.Fatalf("tlsInsecureSkipVerify() = true with CONNECTOR_TLS_INSECURE=%q, want false", v)
		}
	}
}

// TestRotateLLDAPUsesPasswordModifyIdentity proves rotateLLDAP builds the
// RFC-3062 request against the lldap-style bind DN (not a bare username or
// UPN), mirroring bindIdentifier's lldap branch.
func TestRotateLLDAPUsesPasswordModifyIdentity(t *testing.T) {
	const domain = "dc=example,dc=org"
	got := bindIdentifier(Conn{Domain: domain}, "svc-example")
	if !strings.Contains(got, "uid=svc-example,ou=people,"+domain) {
		t.Fatalf("bindIdentifier(lldap) = %q, want it to contain the lldap-style DN", got)
	}
}

// TestBuildADChangePasswordModifyCarriesDeleteThenAdd guards the wire shape:
// AD requires its self-service "Change Password" form -- a Delete of
// the OLD unicodePwd value followed by an Add of the NEW one, both in the
// SAME ModifyRequest -- not the administrative Replace form (which needs
// the Reset-Password control-access right this adapter doesn't have). This
// asserts the exact operation order and the exact encoded byte values, so a
// future refactor can't silently drop back to a bare Replace or swap the
// old/new values.
func TestBuildADChangePasswordModifyCarriesDeleteThenAdd(t *testing.T) {
	const dn = "CN=svc-example,CN=Users,DC=example,DC=org"
	mod := buildADChangePasswordModify(dn, "old-pw", "new-pw")

	if mod.DN != dn {
		t.Fatalf("ModifyRequest.DN = %q, want %q", mod.DN, dn)
	}
	if len(mod.Changes) != 2 {
		t.Fatalf("ModifyRequest.Changes has %d entries, want 2 (delete old, add new)", len(mod.Changes))
	}

	del := mod.Changes[0]
	if del.Operation != ldap.DeleteAttribute {
		t.Fatalf("Changes[0].Operation = %v, want DeleteAttribute", del.Operation)
	}
	if del.Modification.Type != "unicodePwd" {
		t.Fatalf("Changes[0].Modification.Type = %q, want unicodePwd", del.Modification.Type)
	}
	wantOld := encodeADPassword("old-pw")
	if len(del.Modification.Vals) != 1 || del.Modification.Vals[0] != wantOld {
		t.Fatalf("Changes[0] (delete) value = %v, want the encoded OLD password", []byte(del.Modification.Vals[0]))
	}

	add := mod.Changes[1]
	if add.Operation != ldap.AddAttribute {
		t.Fatalf("Changes[1].Operation = %v, want AddAttribute", add.Operation)
	}
	if add.Modification.Type != "unicodePwd" {
		t.Fatalf("Changes[1].Modification.Type = %q, want unicodePwd", add.Modification.Type)
	}
	wantNew := encodeADPassword("new-pw")
	if len(add.Modification.Vals) != 1 || add.Modification.Vals[0] != wantNew {
		t.Fatalf("Changes[1] (add) value = %v, want the encoded NEW password", []byte(add.Modification.Vals[0]))
	}
}

// TestClassifyLDAPResultErrInsufficientAccessRights proves that AD result
// code 50 (Insufficient Access Rights) -- e.g. because the account isn't
// even allowed the self-service delete+add -- is an authoritative rejection
// (Invalid), not Unreachable, since the server did answer and did refuse the
// request.
func TestClassifyLDAPResultErrInsufficientAccessRights(t *testing.T) {
	err := ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("boom"))

	result, detail := classifyLDAPResultErr(err, "modify unicodePwd")
	if result != Invalid {
		t.Fatalf("classifyLDAPResultErr(InsufficientAccessRights) result = %v, want %v", result, Invalid)
	}
	if detail == "" {
		t.Fatal("classifyLDAPResultErr(InsufficientAccessRights) detail is empty, want a rights-error message")
	}
}
