// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/messages"
)

func TestKerberosRegistered(t *testing.T) {
	if _, ok := Get("kerberos"); !ok {
		t.Fatal(`Get("kerberos") ok = false, want true (kerberosAdapter should register itself in init)`)
	}
}

// TestKerberosUnreachable exercises the adapter end-to-end (no live KDC
// required) against a host/port that is guaranteed dead: port 1 on loopback
// is a privileged port nothing binds to in this test environment.
func TestKerberosUnreachable(t *testing.T) {
	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 1, Realm: "EXAMPLE.ORG"}
	cred := Cred{Username: "whoever", Password: "whatever"}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Unreachable {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
	if detail == "" {
		t.Fatal("Validate() detail is empty, want a failure message")
	}
}

// TestKerberosNoRealm covers the local (no-KDC-needed) validation guard: an
// empty Realm and Domain can never produce a usable AS-REQ.
func TestKerberosNoRealm(t *testing.T) {
	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := Conn{Host: "127.0.0.1", Port: 88}
	cred := Cred{Username: "whoever", Password: "whatever"}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Unreachable {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
}

// dialDevKDC skips the calling test if addr isn't reachable, so the live
// Invalid/Valid tests below degrade to a skip instead of a hang/failure
// when no KDC (such as a Samba AD DC) is available.
func dialDevKDC(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Skipf("KDC not reachable at %s: %v", addr, err)
	}
	_ = conn.Close()
}

// TestKerberosInvalid proves the Invalid path (AS-REQ rejected with
// KDC_ERR_PREAUTH_FAILED / KDC_ERR_C_PRINCIPAL_UNKNOWN) against a real KDC.
// It is skipped by default because it needs a live KDC, such as a Samba AD
// DC. With one running, run:
//
//	KRB_TEST_KDC=<host:port> KRB_TEST_REALM=<REALM> \
//	    go test ./internal/adapter/ -run TestKerberosInvalid -v
func TestKerberosInvalid(t *testing.T) {
	kdc := os.Getenv("KRB_TEST_KDC")
	realm := os.Getenv("KRB_TEST_REALM")
	if kdc == "" || realm == "" {
		t.Skip("set KRB_TEST_KDC=<host:port> and KRB_TEST_REALM=<REALM> to run against a live Samba AD DC")
	}
	dialDevKDC(t, kdc)

	host, portStr, err := net.SplitHostPort(kdc)
	if err != nil {
		t.Fatalf("KRB_TEST_KDC=%q must be host:port: %v", kdc, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("KRB_TEST_KDC=%q has a non-numeric port: %v", kdc, err)
	}

	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := Conn{Host: host, Port: port, Realm: realm}
	cred := Cred{Username: "definitely-not-a-real-account", Password: "wrong-password"}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Invalid {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Invalid, detail)
	}
}

// TestKerberosValid proves the Valid path against a real, seeded Kerberos
// account. Skipped by default for the same reason as TestKerberosInvalid
// (it needs a live KDC). With a seeded account on one, run:
//
//	KRB_TEST_KDC=<host:port> KRB_TEST_REALM=<REALM> \
//	KRB_TEST_USER=<username> KRB_TEST_PASSWORD=<password> \
//	    go test ./internal/adapter/ -run TestKerberosValid -v
func TestKerberosValid(t *testing.T) {
	kdc := os.Getenv("KRB_TEST_KDC")
	realm := os.Getenv("KRB_TEST_REALM")
	user := os.Getenv("KRB_TEST_USER")
	password := os.Getenv("KRB_TEST_PASSWORD")
	if kdc == "" || realm == "" || user == "" || password == "" {
		t.Skip("set KRB_TEST_KDC=<host:port>, KRB_TEST_REALM=<REALM>, KRB_TEST_USER and KRB_TEST_PASSWORD to run against a live, seeded Samba AD DC account")
	}
	dialDevKDC(t, kdc)

	host, portStr, err := net.SplitHostPort(kdc)
	if err != nil {
		t.Fatalf("KRB_TEST_KDC=%q must be host:port: %v", kdc, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("KRB_TEST_KDC=%q has a non-numeric port: %v", kdc, err)
	}

	a, ok := Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn := Conn{Host: host, Port: port, Realm: realm}
	cred := Cred{Username: user, Password: password}

	result, detail := a.Validate(ctx, conn, cred)
	if result != Valid {
		t.Fatalf("Validate() result = %v, want %v (detail=%q)", result, Valid, detail)
	}
}

// TestClassifyKrbErr is a table test of the pure error-classification logic,
// covering both routes classifyKrbErr uses (see its doc comment):
//   - errors.As reaching a messages.KRBError, bare or wrapped with %w.
//   - the string-matching fallback, needed because gokrb5's real Login()
//     errors are wrapped in krberror.Krberror, which does not implement
//     Unwrap and so cannot be reached by errors.As -- only its formatted
//     Error() text (which embeds errorcode.Lookup's description) survives.
//
// This is what proves the Invalid/Valid classification without a live KDC:
// the synthetic errors here reproduce the two shapes a real Login() call can
// hand back.
func TestClassifyKrbErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Result
	}{
		{
			name: "bare KRBError PREAUTH_FAILED via errors.As",
			err:  messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED},
			want: Invalid,
		},
		{
			name: "bare KRBError C_PRINCIPAL_UNKNOWN via errors.As",
			err:  messages.KRBError{ErrorCode: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN},
			want: Invalid,
		},
		{
			name: "KRBError wrapped with %w for an unrelated code stays Unreachable",
			err:  fmt.Errorf("as exchange: %w", messages.KRBError{ErrorCode: errorcode.KDC_ERR_KEY_EXPIRED}),
			want: Unreachable,
		},
		{
			name: "KRBError wrapped with %w still reaches errors.As",
			err:  fmt.Errorf("as exchange: %w", messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}),
			want: Invalid,
		},
		{
			// Simulates the real shape of a Login() error: gokrb5's
			// krberror.Krberror has flattened the KRBError into a string
			// (via fmt's %s, not %w), so errors.As can no longer reach it --
			// only the fallback text match can classify this.
			name: "krberror-shaped text, preauth failed",
			err:  errors.New("[Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: " + messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}.Error()),
			want: Invalid,
		},
		{
			name: "krberror-shaped text, principal unknown",
			err:  errors.New("[Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: " + messages.KRBError{ErrorCode: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN}.Error()),
			want: Invalid,
		},
		{
			name: "krberror-shaped text, unrelated KDC error stays Unreachable",
			err:  errors.New("[Root cause: KDC_Error] KDC_Error: AS Exchange Error: kerberos error response from KDC: " + messages.KRBError{ErrorCode: errorcode.KDC_ERR_KEY_EXPIRED}.Error()),
			want: Unreachable,
		},
		{
			name: "plain network error",
			err:  errors.New("error sending to a KDC: dial udp 127.0.0.1:1: connect: connection refused"),
			want: Unreachable,
		},
		{
			name: "plain config error",
			err:  errors.New("client krb5 config does not have any defined KDCs for the default realm"),
			want: Unreachable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, detail := classifyKrbErr(tt.err)
			if result != tt.want {
				t.Fatalf("classifyKrbErr(%v) result = %v, want %v (detail=%q)", tt.err, result, tt.want, detail)
			}
			if detail == "" {
				t.Fatal("classifyKrbErr() detail is empty, want the error message")
			}
		})
	}
}

func TestKerberosRealm(t *testing.T) {
	tests := []struct {
		name string
		conn Conn
		want string
	}{
		{name: "realm set", conn: Conn{Realm: "example.org"}, want: "EXAMPLE.ORG"},
		{name: "realm takes precedence over domain", conn: Conn{Realm: "one.example.org", Domain: "two.example.org"}, want: "ONE.EXAMPLE.ORG"},
		{name: "domain fallback", conn: Conn{Domain: "corp.example.org"}, want: "CORP.EXAMPLE.ORG"},
		{name: "neither set", conn: Conn{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kerberosRealm(tt.conn); got != tt.want {
				t.Fatalf("kerberosRealm(%+v) = %q, want %q", tt.conn, got, tt.want)
			}
		})
	}
}
