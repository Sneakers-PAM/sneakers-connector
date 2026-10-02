// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// devLLDAPAddr is where the live tests expect an lldap listener: a local
// lldap container with its LDAP port published on 23890 (CI runs one as a
// service container).
const devLLDAPAddr = "localhost:23890"

// devLLDAPBaseDN is lldap's configured base DN (the container's
// LLDAP_LDAP_BASE_DN). Conn.Domain set to this value tells bindIdentifier
// to build an lldap-style "uid=<user>,ou=people,<base>" bind DN rather
// than an AD-style UPN.
const devLLDAPBaseDN = "dc=example,dc=org"

func dialDevLLDAP(t *testing.T) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", devLLDAPAddr, time.Second)
	if err != nil {
		t.Skipf("lldap not reachable at %s (start an lldap container with base DN %s): %v", devLLDAPAddr, devLLDAPBaseDN, err)
	}
	_ = conn.Close()
}

func TestLDAPRegistered(t *testing.T) {
	for _, protocol := range []string{"ldap", "ldaps"} {
		if _, ok := Get(protocol); !ok {
			t.Fatalf("Get(%q) ok = false, want true (ldapAdapter should register itself in init)", protocol)
		}
	}
}

func TestLDAPUnreachable(t *testing.T) {
	a, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Port 1 on loopback is never listening, so the dial itself should fail
	// fast rather than hang for the full context timeout.
	conn := Conn{Host: "127.0.0.1", Port: 1}
	cred := Cred{Username: "whoever", Password: "whatever"}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Unreachable {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
	if detail == "" {
		t.Fatal("Validate() detail is empty, want a dial-failure message")
	}
}

// TestLDAPInvalidCreds binds against the live lldap as an account that
// does not exist, using the lldap-style bind DN (Conn.Domain set to the
// base DN triggers bindIdentifier's "uid=...,ou=people,..." form -- lldap
// rejects a bare username or UPN with a naming-violation error, not
// invalid-credentials). lldap returns LDAP result 49 (invalid credentials)
// for both unknown accounts and wrong passwords, so this exercises the
// Invalid path without needing a seeded account.
func TestLDAPInvalidCreds(t *testing.T) {
	dialDevLLDAP(t)

	a, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "localhost", Port: 23890, Domain: devLLDAPBaseDN}
	cred := Cred{Username: "definitely-not-a-real-account", Password: "wrong-password"}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Invalid {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Invalid, detail)
	}
}

// TestLDAPValid proves the Valid path against a real, seeded lldap account.
// It is skipped by default because the test lldap starts with no bind
// account of its own. To run it against one that has a seeded account:
//
//	LDAP_TEST_VALID=1 LDAP_TEST_USER=<username> LDAP_TEST_PASSWORD=<password> \
//	    go test ./internal/adapter/ -run TestLDAPValid -v
func TestLDAPValid(t *testing.T) {
	if os.Getenv("LDAP_TEST_VALID") != "1" {
		t.Skip("set LDAP_TEST_VALID=1 plus LDAP_TEST_USER/LDAP_TEST_PASSWORD to run against a seeded lldap account")
	}
	dialDevLLDAP(t)

	user := os.Getenv("LDAP_TEST_USER")
	password := os.Getenv("LDAP_TEST_PASSWORD")
	if user == "" || password == "" {
		t.Fatal("LDAP_TEST_USER and LDAP_TEST_PASSWORD must be set when LDAP_TEST_VALID=1")
	}

	a, ok := Get("ldap")
	if !ok {
		t.Fatal("ldap adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "localhost", Port: 23890, Domain: devLLDAPBaseDN}
	cred := Cred{Username: user, Password: password}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Valid {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Valid, detail)
	}
}
