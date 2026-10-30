// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// CertificateMismatchError is the error a pinned TLS connection fails with
// when the server's chain matches none of the target's pins. It names the
// presented fingerprints (leaf first) next to the pinned ones, so an admin
// can compare the old and new certificate before re-pinning.
type CertificateMismatchError struct {
	Presented []string
	Pinned    []string
}

func (e *CertificateMismatchError) Error() string {
	return fmt.Sprintf("certificate matches none of the target's pins: presented sha256 %s; pinned sha256 %s",
		strings.Join(e.Presented, ", "), strings.Join(e.Pinned, ", "))
}

// certFingerprint is the SHA-256 of a certificate's DER, in lower-case hex:
// the form a TLS pin is compared in.
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// parseTLSPins normalises pins to lower-case hex SHA-256 fingerprints. It
// accepts an optional "sha256:" prefix, colons between bytes and any case,
// and drops anything that isn't a SHA-256 fingerprint.
func parseTLSPins(pins []string) []string {
	var out []string
	for _, p := range pins {
		p = strings.TrimSpace(p)
		if len(p) > 7 && strings.EqualFold(p[:7], "sha256:") {
			p = p[7:]
		}
		p = strings.ToLower(strings.ReplaceAll(p, ":", ""))
		if b, err := hex.DecodeString(p); err != nil || len(b) != sha256.Size {
			continue
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// pinnedTLSConfig returns the client config for a TLS connection to host.
// With no usable pin it is the standard check against the system roots.
// With pins, the standard chain check is replaced, never dropped: Go's
// built-in check can only trust a CA pool, and a pin can name the server's
// own certificate, so VerifyConnection makes the whole decision (see
// verifyPinnedChain) and fails the handshake before any credential is sent.
func pinnedTLSConfig(host string, pins []string) *tls.Config {
	usable := parseTLSPins(pins)
	if len(usable) == 0 {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- the built-in check is replaced by VerifyConnection, which verifies the pin, dates and host name.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPinnedChain(cs.PeerCertificates, host, usable, time.Now())
		},
	}
}

// verifyPinnedChain accepts chain (the server's certificates, leaf first)
// for host at now when:
//   - the leaf is within its validity dates and covers host, and
//   - the leaf's fingerprint is pinned, or a pinned certificate in the chain
//     verifies the leaf as its root (through the other certificates the
//     server sent), which is how a CA pin survives a routine renewal.
//
// The errors for dates and host name are the x509 package's own, so they
// read the same as an unpinned failure.
func verifyPinnedChain(chain []*x509.Certificate, host string, pins []string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("tls: the server sent no certificate")
	}
	leaf := chain[0]
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired,
			Detail: fmt.Sprintf("current time %s is outside %s to %s", now.UTC().Format(time.RFC3339),
				leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))}
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return err
	}
	if slices.Contains(pins, certFingerprint(leaf)) {
		return nil
	}
	for i, ca := range chain[1:] {
		if !slices.Contains(pins, certFingerprint(ca)) {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		inters := x509.NewCertPool()
		for j, c := range chain[1:] {
			if j != i {
				inters.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: inters,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err == nil {
			return nil
		}
	}
	presented := make([]string, 0, len(chain))
	for _, c := range chain {
		presented = append(presented, certFingerprint(c))
	}
	return &CertificateMismatchError{Presented: presented, Pinned: pins}
}
