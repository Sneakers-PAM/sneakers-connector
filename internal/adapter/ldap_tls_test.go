// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func ldapsAdapter(t *testing.T) Adapter {
	t.Helper()
	t.Setenv("CONNECTOR_TLS_INSECURE", "")
	a, ok := Get("ldaps")
	if !ok {
		t.Fatal("ldaps adapter not registered")
	}
	return a
}

func validateLDAPS(t *testing.T, port int) (Result, string) {
	t.Helper()
	a := ldapsAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.Validate(ctx, Conn{Host: "127.0.0.1", Port: port, UseTLS: true, Domain: "ad.example.org"}, Cred{Username: "svc-example", Password: "not-sent"})
}

func wantDetail(t *testing.T, detail string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(detail, p) {
			t.Errorf("detail = %q, want it to contain %q", detail, p)
		}
	}
}

func TestLDAPSUnknownCAIsUntrustedCertificate(t *testing.T) {
	root := newTestCA(t, "Example Root CA", nil)
	inter := newTestCA(t, "Example Intermediate CA G1", root)
	port := serveTLS(t, loopbackLeaf(t, inter))

	result, detail := validateLDAPS(t, port)
	if result != UntrustedCertificate {
		t.Fatalf("result = %v, want %v (detail=%q)", result, UntrustedCertificate, detail)
	}
	wantDetail(t, detail, "untrusted certificate", "signed by Example Intermediate CA G1, which isn't in the trusted CA list")
}

func TestLDAPSExpiredCertificateIsUntrustedCertificate(t *testing.T) {
	root := newTestCA(t, "Example Root CA", nil)
	cert := root.issueLeaf(t, leafOpts{
		cn:        "dc01.ad.example.org",
		dnsNames:  []string{"dc01.ad.example.org"},
		ips:       []net.IP{net.IPv4(127, 0, 0, 1)},
		notBefore: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		notAfter:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	port := serveTLS(t, cert)

	result, detail := validateLDAPS(t, port)
	if result != UntrustedCertificate {
		t.Fatalf("result = %v, want %v (detail=%q)", result, UntrustedCertificate, detail)
	}
	wantDetail(t, detail, "untrusted certificate", "dc01.ad.example.org", "expired on 2026-01-02")
}

func TestLDAPSNotYetValidCertificateIsUntrustedCertificate(t *testing.T) {
	root := newTestCA(t, "Example Root CA", nil)
	cert := root.issueLeaf(t, leafOpts{
		cn:        "dc01.ad.example.org",
		dnsNames:  []string{"dc01.ad.example.org"},
		notBefore: time.Now().Add(72 * time.Hour),
		notAfter:  time.Now().Add(96 * time.Hour),
	})
	port := serveTLS(t, cert)

	result, detail := validateLDAPS(t, port)
	if result != UntrustedCertificate {
		t.Fatalf("result = %v, want %v (detail=%q)", result, UntrustedCertificate, detail)
	}
	wantDetail(t, detail, "untrusted certificate", "isn't valid until")
}

func TestLDAPSHostNameMismatchIsUntrustedCertificate(t *testing.T) {
	root := newTestCA(t, "Example Root CA", nil)
	cert := root.issueLeaf(t, leafOpts{cn: "dc02.ad.example.org", dnsNames: []string{"dc02.ad.example.org"}})
	port := serveTLS(t, cert)

	result, detail := validateLDAPS(t, port)
	if result != UntrustedCertificate {
		t.Fatalf("result = %v, want %v (detail=%q)", result, UntrustedCertificate, detail)
	}
	wantDetail(t, detail, "untrusted certificate", "is for dc02.ad.example.org, not 127.0.0.1")
}

func TestLDAPSHandshakeTimeoutStaysUnreachable(t *testing.T) {
	port := serveSilent(t)

	result, detail := validateLDAPS(t, port)
	if result != Unreachable {
		t.Fatalf("result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
}

func TestLDAPSRefusedStaysUnreachable(t *testing.T) {
	result, detail := validateLDAPS(t, 1)
	if result != Unreachable {
		t.Fatalf("result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
}

func TestLDAPSRotateUntrustedCertificate(t *testing.T) {
	root := newTestCA(t, "Example Root CA", nil)
	port := serveTLS(t, loopbackLeaf(t, root))
	a := ldapsAdapter(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, detail := a.Rotate(ctx, Conn{Host: "127.0.0.1", Port: port, UseTLS: true, Domain: "ad.example.org"}, Cred{Username: "svc-example", Password: "not-sent"}, "never-sent")
	if result != UntrustedCertificate {
		t.Fatalf("result = %v, want %v (detail=%q)", result, UntrustedCertificate, detail)
	}
	wantDetail(t, detail, "signed by Example Root CA, which isn't in the trusted CA list")
}

func TestUntrustedCertificateString(t *testing.T) {
	if got := UntrustedCertificate.String(); got != "untrusted_certificate" {
		t.Fatalf("String() = %q, want %q", got, "untrusted_certificate")
	}
}
