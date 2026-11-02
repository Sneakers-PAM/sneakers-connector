// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultScanTimeout bounds a whole TLS scan: the TCP connect plus the
// handshake up to the server's certificate.
const DefaultScanTimeout = 5 * time.Second

// The outcomes a failed scan reports.
const (
	// ScanUnreachable means the TCP connect failed (DNS, refused, timeout).
	ScanUnreachable = "unreachable"
	// ScanHandshakeFailed means the target answered but sent no certificate
	// (not TLS, a timeout mid-handshake, or no protocol version in common).
	ScanHandshakeFailed = "handshake_failed"
)

// ScanError is a failed scan, with the outcome to log and report.
type ScanError struct {
	Outcome string
	Err     error
}

func (e *ScanError) Error() string { return e.Outcome + ": " + e.Err.Error() }

func (e *ScanError) Unwrap() error { return e.Err }

// ScannedCertificate is one certificate a server sent, described for a
// person to check before pinning it.
type ScannedCertificate struct {
	Subject           string
	CommonName        string
	DNSNames          []string
	IPAddresses       []string
	Issuer            string
	NotBefore         time.Time
	NotAfter          time.Time
	FingerprintSHA256 string
	SerialNumber      string
	IsCA              bool
	SelfSigned        bool
	// Pinnable reports whether this fingerprint as the target's only pin
	// would make the connector trust the target now (see verifyPinnedChain).
	Pinnable bool
}

// TLSScan is what a TLS scan of a target read.
type TLSScan struct {
	// Address is the ip:port the scan connected to.
	Address string
	// ServerName is the host name the chain was checked against.
	ServerName string
	TLSVersion string
	// Chain is the certificates the server sent, in its order, leaf first.
	Chain []ScannedCertificate
	// SystemTrusted reports whether the chain verifies against the system
	// roots without a pin; SystemTrustDetail says why not.
	SystemTrusted     bool
	SystemTrustDetail string
	HostNameMatches   bool
}

// errChainRead stops the handshake once the server's chain has arrived,
// before the client's Finished message, so no application data can follow.
var errChainRead = errors.New("certificate chain read")

// ScanTLSCertificate connects to host:port, reads the certificate chain the
// server sends during the TLS handshake and abandons the handshake, all
// within timeout (DefaultScanTimeout when zero or less). It never sends
// application data, so nothing is bound or authenticated on the target.
//
// Reading a chain the connector may not trust yet is the point of a scan, so
// the built-in check is off here only; the chain is then checked against the
// system roots and against each certificate as a pin, and the result says
// which of them would be trusted. Nothing here is a pin or a credential path.
func ScanTLSCertificate(ctx context.Context, host string, port int, timeout time.Duration) (TLSScan, error) {
	if timeout <= 0 {
		timeout = DefaultScanTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSScan{}, &ScanError{Outcome: ScanUnreachable, Err: err}
	}
	defer func() { _ = raw.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return TLSScan{}, &ScanError{Outcome: ScanHandshakeFailed, Err: err}
		}
	}

	var state *tls.ConnectionState
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- a scan reads a chain that may not be trusted yet; VerifyConnection aborts the handshake before any data, and the chain is verified below.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			state = &cs
			return errChainRead
		},
	}
	err = tls.Client(raw, cfg).HandshakeContext(ctx)
	if state == nil || len(state.PeerCertificates) == 0 {
		if err == nil {
			err = errors.New("handshake ended without a certificate")
		}
		return TLSScan{}, &ScanError{Outcome: ScanHandshakeFailed, Err: err}
	}
	return describeScan(raw.RemoteAddr().String(), host, state.Version, state.PeerCertificates, time.Now()), nil
}

// describeScan builds the scan result for chain (leaf first) sent by the
// server at addr, checked for host at now.
func describeScan(addr, host string, version uint16, chain []*x509.Certificate, now time.Time) TLSScan {
	leaf := chain[0]
	scan := TLSScan{
		Address:         addr,
		ServerName:      host,
		TLSVersion:      tls.VersionName(version),
		HostNameMatches: leaf.VerifyHostname(host) == nil,
	}
	inters := x509.NewCertPool()
	for _, c := range chain[1:] {
		inters.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	scan.SystemTrusted = verr == nil
	if verr != nil {
		scan.SystemTrustDetail = describeCertificateFailure(verr, chain, host, now)
	}
	for _, c := range chain {
		fp := certFingerprint(c)
		ips := make([]string, 0, len(c.IPAddresses))
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		scan.Chain = append(scan.Chain, ScannedCertificate{
			Subject:           c.Subject.String(),
			CommonName:        c.Subject.CommonName,
			DNSNames:          append([]string{}, c.DNSNames...),
			IPAddresses:       ips,
			Issuer:            c.Issuer.String(),
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			FingerprintSHA256: fp,
			SerialNumber:      c.SerialNumber.Text(16),
			IsCA:              c.IsCA,
			SelfSigned:        selfSigned(c),
			Pinnable:          verifyPinnedChain(chain, host, []string{fp}, now) == nil,
		})
	}
	return scan
}

// String names a scan in a log line: the address and the leaf's fingerprint.
func (s TLSScan) String() string {
	if len(s.Chain) == 0 {
		return s.Address
	}
	return fmt.Sprintf("%s sha256 %s", s.Address, s.Chain[0].FingerprintSHA256)
}

// selfSigned reports whether c is signed by its own key. It checks the
// signature directly rather than through CheckSignatureFrom, which also
// demands a CA, so a self-signed server certificate (a lab domain
// controller's) reads as self-signed too.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
