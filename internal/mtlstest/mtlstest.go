// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package mtlstest makes throwaway certificate authorities and service
// certificates for tests of the mutual TLS paths. Nothing here is for use
// outside tests.
package mtlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
)

// CA is a certificate authority that can issue service certificates.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	n    int64
}

// NewCA makes a self-signed CA named name.
func NewCA(t *testing.T, name string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &CA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), n: 1}
}

// Issue writes a service certificate for the loopback address (client and
// server use) into a fresh directory and returns the three file paths. The
// CA file holds this CA only.
func (ca *CA) Issue(t *testing.T, name string) mtls.Files {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	ca.n++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.n),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{"localhost", name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("leaf key der: %v", err)
	}
	dir := t.TempDir()
	f := mtls.Files{Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), CA: filepath.Join(dir, "ca.crt")}
	write := func(path string, b []byte) {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(f.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(f.Key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	write(f.CA, ca.pem)
	return f
}

// Trusting returns f with its CA file replaced by one holding the given CAs'
// certificates, so a client built from f can verify servers signed by them.
func Trusting(t *testing.T, f mtls.Files, cas ...*CA) mtls.Files {
	t.Helper()
	var all []byte
	for _, ca := range cas {
		all = append(all, ca.pem...)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, all, 0o600); err != nil {
		t.Fatalf("write ca bundle: %v", err)
	}
	f.CA = path
	return f
}
