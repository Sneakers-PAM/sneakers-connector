// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func scanLoopback(t *testing.T, port int) TLSScan {
	t.Helper()
	scan, err := ScanTLSCertificate(context.Background(), "127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return scan
}

func TestScanReturnsTheChainTheServerSends(t *testing.T) {
	dc := newEnterpriseDC(t)
	scan := scanLoopback(t, dc.port)

	if want := fmt.Sprintf("127.0.0.1:%d", dc.port); scan.Address != want {
		t.Errorf("address %q, want %q", scan.Address, want)
	}
	if scan.ServerName != "127.0.0.1" {
		t.Errorf("server name %q", scan.ServerName)
	}
	if !strings.HasPrefix(scan.TLSVersion, "TLS 1.") {
		t.Errorf("tls version %q", scan.TLSVersion)
	}
	if len(scan.Chain) != 2 {
		t.Fatalf("chain has %d certificates, want the leaf and the intermediate", len(scan.Chain))
	}
	leaf, inter := scan.Chain[0], scan.Chain[1]
	if leaf.FingerprintSHA256 != fingerprint(dc.leaf.Leaf) {
		t.Errorf("leaf fingerprint %s, want %s", leaf.FingerprintSHA256, fingerprint(dc.leaf.Leaf))
	}
	if inter.FingerprintSHA256 != fingerprint(dc.inter.cert) {
		t.Errorf("intermediate fingerprint %s, want %s", inter.FingerprintSHA256, fingerprint(dc.inter.cert))
	}
	if leaf.CommonName != "dc01.ad.example.org" || !strings.Contains(leaf.Subject, "CN=dc01.ad.example.org") {
		t.Errorf("leaf subject %q, common name %q", leaf.Subject, leaf.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "dc01.ad.example.org" {
		t.Errorf("leaf DNS names %v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0] != "127.0.0.1" {
		t.Errorf("leaf IP addresses %v", leaf.IPAddresses)
	}
	if !strings.Contains(leaf.Issuer, "CN=Example Intermediate CA G1") {
		t.Errorf("leaf issuer %q", leaf.Issuer)
	}
	if !leaf.NotBefore.Equal(dc.leaf.Leaf.NotBefore) || !leaf.NotAfter.Equal(dc.leaf.Leaf.NotAfter) {
		t.Errorf("leaf dates %s to %s, want %s to %s", leaf.NotBefore, leaf.NotAfter, dc.leaf.Leaf.NotBefore, dc.leaf.Leaf.NotAfter)
	}
	if leaf.SerialNumber != dc.leaf.Leaf.SerialNumber.Text(16) {
		t.Errorf("leaf serial %q", leaf.SerialNumber)
	}
	if leaf.IsCA || leaf.SelfSigned {
		t.Errorf("leaf is CA %v, self-signed %v", leaf.IsCA, leaf.SelfSigned)
	}
	if !inter.IsCA || inter.SelfSigned {
		t.Errorf("intermediate is CA %v, self-signed %v", inter.IsCA, inter.SelfSigned)
	}
	if !scan.HostNameMatches {
		t.Error("host name should match 127.0.0.1")
	}
}

func TestScanOffersTheLeafAndTheIssuingCAAsPins(t *testing.T) {
	dc := newEnterpriseDC(t)
	scan := scanLoopback(t, dc.port)
	if !scan.Chain[0].Pinnable || !scan.Chain[1].Pinnable {
		t.Fatalf("pinnable: leaf %v, intermediate %v; want both", scan.Chain[0].Pinnable, scan.Chain[1].Pinnable)
	}
}

func TestScanReportsAnEnterpriseCertificateAsNotSystemTrusted(t *testing.T) {
	dc := newEnterpriseDC(t)
	scan := scanLoopback(t, dc.port)
	if scan.SystemTrusted {
		t.Fatal("an enterprise-issued certificate is not in the system roots")
	}
	if !strings.Contains(scan.SystemTrustDetail, "isn't in the trusted CA list") {
		t.Fatalf("system trust detail %q", scan.SystemTrustDetail)
	}
}

func TestAScannedFingerprintPinsTheTarget(t *testing.T) {
	dc := newEnterpriseDC(t)
	scan := scanLoopback(t, dc.port)

	if err := dialPinned(t, pinnedConn(dc.port)); err == nil {
		t.Fatal("dial before the pin succeeded")
	}
	for _, c := range scan.Chain {
		if err := dialPinned(t, pinnedConn(dc.port, c.FingerprintSHA256)); err != nil {
			t.Errorf("dial with %s (%s) pinned: %v", c.CommonName, c.FingerprintSHA256, err)
		}
	}
}

func TestScanOfAnotherHostNameOffersNoPin(t *testing.T) {
	dc := newEnterpriseDC(t)
	scan, err := ScanTLSCertificate(context.Background(), "localhost", dc.port, time.Second)
	if err != nil {
		t.Skipf("localhost does not resolve here: %v", err)
	}
	if scan.HostNameMatches {
		t.Fatal("the certificate doesn't cover localhost")
	}
	for _, c := range scan.Chain {
		if c.Pinnable {
			t.Errorf("%s offered as a pin for a host it doesn't cover", c.CommonName)
		}
	}
	if !strings.Contains(scan.SystemTrustDetail, "not localhost") {
		t.Errorf("system trust detail %q", scan.SystemTrustDetail)
	}
}

func TestScanOfAnExpiredCertificateOffersNoPin(t *testing.T) {
	ca := newTestCA(t, "Example Enterprise Root CA", nil)
	leaf := ca.issueLeaf(t, leafOpts{cn: "dc01.ad.example.org", ips: []net.IP{net.IPv4(127, 0, 0, 1)},
		notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour)})
	scan := scanLoopback(t, serveTLS(t, leaf))
	if len(scan.Chain) != 1 || scan.Chain[0].Pinnable {
		t.Fatalf("an expired certificate was offered as a pin: %+v", scan.Chain)
	}
	if !strings.Contains(scan.SystemTrustDetail, "expired") {
		t.Errorf("system trust detail %q", scan.SystemTrustDetail)
	}
}

func TestScanNeverFinishesTheHandshake(t *testing.T) {
	ca := newTestCA(t, "Example Enterprise Root CA", nil)
	leaf := loopbackLeaf(t, ca)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	result := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12})
		if err := srv.Handshake(); err != nil {
			result <- err
			return
		}
		buf := make([]byte, 1)
		_, err = srv.Read(buf)
		result <- err
	}()

	scanLoopback(t, ln.Addr().(*net.TCPAddr).Port)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("the server read application data from a scan")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the scan end")
	}
}

func TestScanOfAClosedPortIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	_, err = ScanTLSCertificate(context.Background(), "127.0.0.1", port, time.Second)
	var se *ScanError
	if !errors.As(err, &se) || se.Outcome != ScanUnreachable {
		t.Fatalf("err %v, want a ScanError with outcome %q", err, ScanUnreachable)
	}
}

func TestScanOfASilentServerTimesOut(t *testing.T) {
	port := serveSilent(t)
	start := time.Now()
	_, err := ScanTLSCertificate(context.Background(), "127.0.0.1", port, 300*time.Millisecond)
	var se *ScanError
	if !errors.As(err, &se) || se.Outcome != ScanHandshakeFailed {
		t.Fatalf("err %v, want a ScanError with outcome %q", err, ScanHandshakeFailed)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("scan took %s, want it bounded by its timeout", time.Since(start))
	}
}

func TestScanOfAWholeChainMarksTheRootSelfSigned(t *testing.T) {
	root := newTestCA(t, "Example Enterprise Root CA", nil)
	inter := newTestCA(t, "Example Intermediate CA G1", root)
	leaf := loopbackLeaf(t, inter, inter, root)
	scan := scanLoopback(t, serveTLS(t, leaf))
	if len(scan.Chain) != 3 {
		t.Fatalf("chain has %d certificates, want 3", len(scan.Chain))
	}
	r := scan.Chain[2]
	if !r.SelfSigned || !r.IsCA || !r.Pinnable {
		t.Fatalf("root: self-signed %v, CA %v, pinnable %v; want all true", r.SelfSigned, r.IsCA, r.Pinnable)
	}
}
