// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA is a certificate authority made for one test: a root when it has
// no parent, otherwise an intermediate signed by its parent.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var testSerial int64

func nextSerial() *big.Int {
	testSerial++
	return big.NewInt(time.Now().UnixNano() + testSerial)
}

func newTestCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Example Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// leafOpts describes a server certificate. Zero dates mean valid now.
type leafOpts struct {
	cn        string
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

// issueLeaf signs a server certificate and returns it with the chain the
// server presents: the leaf, then each of chain in order.
func (ca *testCA) issueLeaf(t *testing.T, o leafOpts, chain ...*testCA) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: o.cn},
		DNSNames:     o.dnsNames,
		IPAddresses:  o.ips,
		NotBefore:    o.notBefore,
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	out := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		out.Certificate = append(out.Certificate, c.cert.Raw)
	}
	return out
}

// loopbackLeaf is a currently valid certificate for 127.0.0.1.
func loopbackLeaf(t *testing.T, ca *testCA, chain ...*testCA) tls.Certificate {
	t.Helper()
	return ca.issueLeaf(t, leafOpts{cn: "dc01.ad.example.org", dnsNames: []string{"dc01.ad.example.org"}, ips: []net.IP{net.IPv4(127, 0, 0, 1)}}, chain...)
}

// serveTLS starts a loopback listener that completes a TLS handshake with
// cert and then closes the connection. It returns the port.
func serveTLS(t *testing.T, cert tls.Certificate) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
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
	return ln.Addr().(*net.TCPAddr).Port
}

// serveSilent starts a loopback listener that accepts connections and never
// answers, so a TLS handshake against it times out.
func serveSilent(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
