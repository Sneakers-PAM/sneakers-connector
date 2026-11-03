// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/connector/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// serveSelfSigned starts a loopback TLS listener with a self-signed
// certificate for 127.0.0.1 and returns its port and the certificate.
func serveSelfSigned(t *testing.T) (int, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "dc01.ad.example.org"},
		DNSNames:     []string{"dc01.ad.example.org"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_ = tls.Server(c, cfg).Handshake()
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, cert
}

func scanRequest(port int) *connectorv1.ScanTLSCertificateRequest {
	return &connectorv1.ScanTLSCertificateRequest{
		Host:        "127.0.0.1",
		Port:        int32(port),
		TargetId:    "target-1",
		ActorUserId: "user-1",
		Actor:       &connectorv1.ActorContext{UserId: "user-1"},
	}
}

func TestScanTLSCertificateReturnsTheChain(t *testing.T) {
	port, cert := serveSelfSigned(t)
	s := NewTLSScanServer(log.Nop())

	resp, err := s.ScanTLSCertificate(context.Background(), scanRequest(port))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(resp.GetChain()) != 1 {
		t.Fatalf("chain has %d certificates", len(resp.GetChain()))
	}
	sum := sha256.Sum256(cert.Raw)
	got := resp.GetChain()[0]
	if got.GetFingerprintSha256() != hex.EncodeToString(sum[:]) {
		t.Errorf("fingerprint %s", got.GetFingerprintSha256())
	}
	if got.GetCommonName() != "dc01.ad.example.org" || got.GetIssuer() == "" || got.GetSubject() == "" {
		t.Errorf("names: %+v", got)
	}
	if !got.GetNotBefore().AsTime().Equal(cert.NotBefore) || !got.GetNotAfter().AsTime().Equal(cert.NotAfter) {
		t.Errorf("dates %s to %s", got.GetNotBefore().AsTime(), got.GetNotAfter().AsTime())
	}
	if len(got.GetDnsNames()) != 1 || len(got.GetIpAddresses()) != 1 {
		t.Errorf("SANs %v %v", got.GetDnsNames(), got.GetIpAddresses())
	}
	if !got.GetSelfSigned() || !got.GetPinnable() {
		t.Errorf("self-signed %v, pinnable %v", got.GetSelfSigned(), got.GetPinnable())
	}
	if resp.GetAddress() == "" || resp.GetServerName() != "127.0.0.1" || resp.GetTlsVersion() == "" {
		t.Errorf("response %+v", resp)
	}
	if resp.GetSystemTrusted() || resp.GetSystemTrustDetail() == "" || !resp.GetHostNameMatches() {
		t.Errorf("trust: system %v (%q), host %v", resp.GetSystemTrusted(), resp.GetSystemTrustDetail(), resp.GetHostNameMatches())
	}
}

func TestScanTLSCertificateRefusesAnythingButAPerson(t *testing.T) {
	port, _ := serveSelfSigned(t)
	s := NewTLSScanServer(log.Nop())
	for _, kind := range []connectorv1.PrincipalKind{
		connectorv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		connectorv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
		connectorv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN,
	} {
		req := scanRequest(port)
		req.Actor.PrincipalKind = kind
		_, err := s.ScanTLSCertificate(context.Background(), req)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: code %v, want PermissionDenied", kind, status.Code(err))
		}
	}
}

func TestScanTLSCertificateNeedsTheTargetAndThePerson(t *testing.T) {
	s := NewTLSScanServer(log.Nop())
	cases := map[string]func(*connectorv1.ScanTLSCertificateRequest){
		"no host":   func(r *connectorv1.ScanTLSCertificateRequest) { r.Host = "" },
		"no target": func(r *connectorv1.ScanTLSCertificateRequest) { r.TargetId = "" },
		"no actor":  func(r *connectorv1.ScanTLSCertificateRequest) { r.ActorUserId = "" },
		"bad port":  func(r *connectorv1.ScanTLSCertificateRequest) { r.Port = 70000 },
	}
	for name, mutate := range cases {
		req := scanRequest(636)
		mutate(req)
		if _, err := s.ScanTLSCertificate(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code %v, want InvalidArgument", name, status.Code(err))
		}
	}
}

func TestScanTLSCertificateDefaultsToTheLDAPSPort(t *testing.T) {
	s := NewTLSScanServer(log.Nop())
	var gotPort int
	s.scan = func(_ context.Context, _ string, port int, _ time.Duration) (adapter.TLSScan, error) {
		gotPort = port
		return adapter.TLSScan{}, &adapter.ScanError{Outcome: adapter.ScanUnreachable, Err: errors.New("test")}
	}
	req := scanRequest(0)
	_, _ = s.ScanTLSCertificate(context.Background(), req)
	if gotPort != 636 {
		t.Fatalf("port %d, want 636", gotPort)
	}
}

func TestScanTLSCertificateIsRateLimitedPerPerson(t *testing.T) {
	port, _ := serveSelfSigned(t)
	s := NewTLSScanServer(log.Nop())
	now := time.Now()
	s.limit.now = func() time.Time { return now }
	for i := 0; i < scanBurst; i++ {
		if _, err := s.ScanTLSCertificate(context.Background(), scanRequest(port)); err != nil {
			t.Fatalf("scan %d: %v", i+1, err)
		}
	}
	if _, err := s.ScanTLSCertificate(context.Background(), scanRequest(port)); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("scan over the burst: code %v, want ResourceExhausted", status.Code(err))
	}
	other := scanRequest(port)
	other.ActorUserId = "user-2"
	if _, err := s.ScanTLSCertificate(context.Background(), other); err != nil {
		t.Fatalf("another person's scan: %v", err)
	}
	now = now.Add(scanRefill)
	if _, err := s.ScanTLSCertificate(context.Background(), scanRequest(port)); err != nil {
		t.Fatalf("scan after a refill: %v", err)
	}
}

func TestScanTLSCertificateOfAClosedPortIsUnavailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	s := NewTLSScanServer(log.Nop())
	_, err = s.ScanTLSCertificate(context.Background(), scanRequest(port))
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code %v, want Unavailable", status.Code(err))
	}
}
