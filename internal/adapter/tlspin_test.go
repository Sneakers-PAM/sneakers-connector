// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// enterpriseDC is a domain controller whose certificate comes from an
// enterprise CA the connector's system roots don't hold: the server sends
// its leaf and the issuing intermediate.
type enterpriseDC struct {
	root, inter *testCA
	leaf        tls.Certificate
	port        int
}

func newEnterpriseDC(t *testing.T) *enterpriseDC {
	t.Helper()
	root := newTestCA(t, "Example Enterprise Root CA", nil)
	inter := newTestCA(t, "Example Intermediate CA G1", root)
	leaf := loopbackLeaf(t, inter, inter)
	return &enterpriseDC{root: root, inter: inter, leaf: leaf, port: serveTLS(t, leaf)}
}

func pinnedConn(port int, pins ...string) Conn {
	return Conn{Host: "127.0.0.1", Port: port, UseTLS: true, Domain: "ad.example.org", TLSPins: pins}
}

func dialPinned(t *testing.T, c Conn) error {
	t.Helper()
	t.Setenv("CONNECTOR_TLS_INSECURE", "")
	conn, err := dialLDAP(c)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func TestEnterpriseDCFailsBeforeThePinAndVerifiesAfter(t *testing.T) {
	dc := newEnterpriseDC(t)

	if err := dialPinned(t, pinnedConn(dc.port)); err == nil {
		t.Fatal("dial without a pin succeeded, want the enterprise certificate refused")
	}
	if err := dialPinned(t, pinnedConn(dc.port, fingerprint(dc.leaf.Leaf))); err != nil {
		t.Fatalf("dial with the leaf pinned: %v", err)
	}
}

func TestRemovingThePinFailsAgain(t *testing.T) {
	dc := newEnterpriseDC(t)
	if err := dialPinned(t, pinnedConn(dc.port, fingerprint(dc.leaf.Leaf))); err != nil {
		t.Fatalf("dial with the leaf pinned: %v", err)
	}
	if err := dialPinned(t, pinnedConn(dc.port)); err == nil {
		t.Fatal("dial after the pin was removed succeeded, want it refused again")
	}
}

func TestChangedLeafFailsUnderALeafPinButPassesUnderItsCAPin(t *testing.T) {
	dc := newEnterpriseDC(t)
	oldPin := fingerprint(dc.leaf.Leaf)
	renewed := loopbackLeaf(t, dc.inter, dc.inter)
	port := serveTLS(t, renewed)

	a := pinnedLDAPSAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, detail := a.Validate(ctx, pinnedConn(port, oldPin), Cred{Username: "svc-example", Password: "not-sent"})
	if result != CertificateMismatch {
		t.Fatalf("leaf pin, renewed leaf: result = %v, want %v (detail=%q)", result, CertificateMismatch, detail)
	}
	for _, want := range []string{oldPin, fingerprint(renewed.Leaf), "matches none of the target's pins"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail = %q, want it to contain %q", detail, want)
		}
	}

	if err := dialPinned(t, pinnedConn(port, fingerprint(dc.inter.cert))); err != nil {
		t.Fatalf("CA pin, renewed leaf: %v", err)
	}
}

func TestRootCAPinWhenTheServerSendsTheWholeChain(t *testing.T) {
	root := newTestCA(t, "Example Enterprise Root CA", nil)
	inter := newTestCA(t, "Example Intermediate CA G1", root)
	port := serveTLS(t, loopbackLeaf(t, inter, inter, root))
	if err := dialPinned(t, pinnedConn(port, fingerprint(root.cert))); err != nil {
		t.Fatalf("root pin: %v", err)
	}
}

func TestCAPinMustSignTheLeaf(t *testing.T) {
	dc := newEnterpriseDC(t)
	other := newTestCA(t, "Example Other CA", nil)
	// The server presents an unrelated CA certificate in its chain; pinning
	// that one must not vouch for a leaf it never signed.
	port := serveTLS(t, loopbackLeaf(t, dc.inter, dc.inter, other))
	if err := dialPinned(t, pinnedConn(port, fingerprint(other.cert))); err == nil {
		t.Fatal("pin of a CA that didn't sign the leaf was accepted")
	}
}

func TestPinnedLeafStillChecksDatesAndHostName(t *testing.T) {
	root := newTestCA(t, "Example Enterprise Root CA", nil)

	expired := root.issueLeaf(t, leafOpts{
		cn:        "dc01.ad.example.org",
		ips:       []net.IP{net.IPv4(127, 0, 0, 1)},
		notBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err := dialPinned(t, pinnedConn(serveTLS(t, expired), fingerprint(expired.Leaf))); err == nil {
		t.Error("expired pinned leaf was accepted")
	}

	otherHost := root.issueLeaf(t, leafOpts{cn: "dc02.ad.example.org", dnsNames: []string{"dc02.ad.example.org"}})
	if err := dialPinned(t, pinnedConn(serveTLS(t, otherHost), fingerprint(otherHost.Leaf))); err == nil {
		t.Error("pinned leaf for another host name was accepted")
	}
}

func TestPinFormatsAreNormalised(t *testing.T) {
	dc := newEnterpriseDC(t)
	fp := strings.ToUpper(fingerprint(dc.leaf.Leaf))
	var colons []string
	for i := 0; i < len(fp); i += 2 {
		colons = append(colons, fp[i:i+2])
	}
	for _, pin := range []string{"SHA256:" + fp, strings.Join(colons, ":"), " sha256:" + strings.ToLower(fp) + " "} {
		if err := dialPinned(t, pinnedConn(dc.port, pin)); err != nil {
			t.Errorf("pin %q: %v", pin, err)
		}
	}
}

func TestUnusablePinsFallBackToTheSystemRoots(t *testing.T) {
	dc := newEnterpriseDC(t)
	if err := dialPinned(t, pinnedConn(dc.port, "not-a-fingerprint")); err == nil {
		t.Fatal("an unusable pin let the enterprise certificate through")
	}
}

func TestPinnedPathNeverSkipsVerification(t *testing.T) {
	cfg := ldapsTLSConfig(pinnedConn(636, strings.Repeat("ab", 32)))
	if cfg.VerifyConnection == nil {
		t.Fatal("pinned config has no VerifyConnection, so nothing checks the certificate")
	}
	if cfg.ServerName != "127.0.0.1" {
		t.Fatalf("ServerName = %q, want the target host", cfg.ServerName)
	}
}

func TestCertificateMismatchString(t *testing.T) {
	if got := CertificateMismatch.String(); got != "certificate_mismatch" {
		t.Fatalf("String() = %q, want %q", got, "certificate_mismatch")
	}
}

func pinnedLDAPSAdapter(t *testing.T) Adapter {
	t.Helper()
	t.Setenv("CONNECTOR_TLS_INSECURE", "")
	a, ok := Get("ldaps")
	if !ok {
		t.Fatal("ldaps adapter not registered")
	}
	return a
}

func TestPinnedTargetThatNeverAnswersStaysUnreachable(t *testing.T) {
	a := pinnedLDAPSAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, detail := a.Validate(ctx, pinnedConn(serveSilent(t), strings.Repeat("ab", 32)), Cred{Username: "svc-example", Password: "not-sent"})
	if result != Unreachable {
		t.Fatalf("result = %v, want %v (detail=%q)", result, Unreachable, detail)
	}
}
