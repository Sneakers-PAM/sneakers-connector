// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// certificateFailure reports whether err is a failed TLS certificate check
// on a connection to host and, when it is, why in words an admin can act
// on: the certificate expired or isn't valid yet, it was issued for another
// host name, or its issuer isn't trusted. Any other error (DNS, refused,
// timeout, a protocol error) is not a certificate failure.
//
// The reason comes from the certificates the server presented, not only
// from the verifier's error, because the platform verifier on some systems
// reports every failure as a bare "certificate is not trusted".
func certificateFailure(err error, host string) (string, bool) {
	var verr *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var chain []*x509.Certificate
	switch {
	case errors.As(err, &verr):
		chain = verr.UnverifiedCertificates
	case errors.As(err, &unknown):
		if unknown.Cert != nil {
			chain = []*x509.Certificate{unknown.Cert}
		}
	case errors.As(err, &invalid):
		if invalid.Cert != nil {
			chain = []*x509.Certificate{invalid.Cert}
		}
	case errors.As(err, &hostname):
		if hostname.Certificate != nil {
			chain = []*x509.Certificate{hostname.Certificate}
		}
	default:
		return "", false
	}
	return "untrusted certificate: " + describeCertificateFailure(err, chain, host, time.Now()), true
}

// describeCertificateFailure names the first thing wrong with chain (leaf
// first) for host at now.
func describeCertificateFailure(err error, chain []*x509.Certificate, host string, now time.Time) string {
	if len(chain) == 0 {
		return err.Error()
	}
	leaf := chain[0]
	name := certName(leaf)
	switch {
	case now.After(leaf.NotAfter):
		return fmt.Sprintf("the certificate for %s expired on %s", name, leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(leaf.NotBefore):
		return fmt.Sprintf("the certificate for %s isn't valid until %s", name, leaf.NotBefore.UTC().Format(time.RFC3339))
	case host != "" && leaf.VerifyHostname(host) != nil:
		return fmt.Sprintf("the certificate is for %s, not %s", strings.Join(certHostNames(leaf), ", "), host)
	}

	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason != x509.Expired {
		return fmt.Sprintf("the certificate for %s was refused: %v", name, invalid)
	}
	top := chain[len(chain)-1]
	return fmt.Sprintf("the certificate for %s is signed by %s, which isn't in the trusted CA list", name, issuerName(top))
}

// certName is the name a certificate is known by: its common name, else
// its first host name, else its full subject.
func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	if names := certHostNames(c); len(names) > 0 {
		return names[0]
	}
	return c.Subject.String()
}

// certHostNames lists the DNS names and IP addresses a certificate covers,
// falling back to its common name when it has neither.
func certHostNames(c *x509.Certificate) []string {
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = append(names, c.Subject.CommonName)
	}
	return names
}

func issuerName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}
