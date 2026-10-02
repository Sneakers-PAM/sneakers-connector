// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshAdapter validates an SSH private key by opening a public-key-authenticated
// connection to the target as the account. It connects only to a host that
// presents one of the target's pinned host keys, the same check the SSH broker
// makes. It never executes a command and never logs key material. Rotation (two-phase authorized_keys swap) is not
// implemented; ssh secrets are heartbeat-only for now.
type sshAdapter struct{}

func init() { Register("ssh", &sshAdapter{}) }

// Validate parses cred's private key and attempts a public-key SSH handshake
// to c as cred.Username. A successful handshake => Valid; an auth rejection by
// a reachable target => Invalid; a target with no usable pin in c.HostKeys =>
// HostKeyNotPinned; a host key matching none of them => HostKeyMismatch; a
// parse failure or dial/handshake transport error => Unreachable. The host key
// is checked during key exchange, before the account's key is offered, and
// the host-key details carry the presented key's SHA256 fingerprint.
func (a *sshAdapter) Validate(ctx context.Context, c Conn, cred Cred) (Result, string) {
	var signer ssh.Signer
	var err error
	if cred.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey([]byte(cred.PrivateKey))
	}
	if err != nil {
		return Unreachable, fmt.Sprintf("parse private key: %v", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dialTimeout) // dialTimeout defined in ldap.go
	}
	pins, pinAlgos := parsePins(c.HostKeys)
	var presented string
	cfg := &ssh.ClientConfig{
		User:              cred.Username,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   pinnedHostKeyCallback(pins, &presented),
		HostKeyAlgorithms: pinAlgos,
		Timeout:           time.Until(deadline),
	}

	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	conn, err := net.DialTimeout("tcp", addr, time.Until(deadline))
	if err != nil {
		return Unreachable, fmt.Sprintf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		switch {
		case errors.Is(err, errHostKeyNotPinned):
			return HostKeyNotPinned, fmt.Sprintf("%v (presented %s)", errHostKeyNotPinned, presented)
		case errors.Is(err, errHostKeyMismatch):
			return HostKeyMismatch, fmt.Sprintf("%v (presented %s)", errHostKeyMismatch, presented)
		}
		// A reachable target that rejects our key surfaces as an auth failure
		// during the handshake; treat that as Invalid, everything else as
		// Unreachable. x/crypto/ssh wraps auth failures with this prefix.
		if isAuthFailure(err) {
			return Invalid, "public-key authentication rejected"
		}
		return Unreachable, fmt.Sprintf("ssh handshake %s: %v", addr, err)
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "validation only")
		}
	}()
	_ = sc.Close()
	return Valid, ""
}

// Rotate is not implemented for ssh; two-phase authorized_keys rotation is a
// future phase. The type-ssh-key type carries no rotation flag, so this is a
// safety net that should never be scheduled.
func (a *sshAdapter) Rotate(_ context.Context, _ Conn, _ Cred, _ string) (Result, string) {
	return Unreachable, "ssh rotation not implemented"
}

// isAuthFailure reports whether err is an SSH authentication rejection (as
// opposed to a transport/dial error).
func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "no supported methods remain")
}

// The two host-key refusals, worded as the SSH broker words them.
var (
	errHostKeyNotPinned = errors.New("host key not pinned for this target")
	errHostKeyMismatch  = errors.New("host key mismatch")
)

// parsePins parses the pinned host keys and lists the host key algorithms to
// ask for, so a host with several keys presents a pinned one. A pin that
// doesn't parse is dropped, which can only make the check stricter.
func parsePins(lines []string) (pins []ssh.PublicKey, algos []string) {
	for _, line := range lines {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		pins = append(pins, pub)
		for _, a := range hostKeyAlgorithmsFor(pub.Type()) {
			if !slices.Contains(algos, a) {
				algos = append(algos, a)
			}
		}
	}
	return pins, algos
}

// hostKeyAlgorithmsFor maps a key type to the host key algorithms that prove
// it. An RSA key signs with SHA-2 only; the SHA-1 "ssh-rsa" algorithm is not
// offered.
func hostKeyAlgorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{keyType}
}

// pinnedHostKeyCallback accepts the host only when it presents one of pins,
// recording the presented key's SHA256 fingerprint in presented.
func pinnedHostKeyCallback(pins []ssh.PublicKey, presented *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		*presented = ssh.FingerprintSHA256(key)
		if len(pins) == 0 {
			return errHostKeyNotPinned
		}
		got := key.Marshal()
		for _, p := range pins {
			if bytes.Equal(p.Marshal(), got) {
				return nil
			}
		}
		return errHostKeyMismatch
	}
}
