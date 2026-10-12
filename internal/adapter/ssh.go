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

// sshAdapter validates an SSH credential by signing in to the target as the
// account: with the private key when the secret has one, otherwise with the
// password. It connects only to a host that presents one of the target's
// pinned host keys, the same check the SSH broker makes, and it never
// contacts a target with no usable pin. It never executes a command and never
// logs key material. Rotation (two-phase authorized_keys swap) is not
// implemented; ssh secrets are heartbeat-only for now.
type sshAdapter struct{}

func init() { Register("ssh", &sshAdapter{}) }

// NotPinnedDetail is the detail reported for a target with no usable host-key
// pin. No connection is made to such a target.
const NotPinnedDetail = "host key not pinned for this target: pin the host key first; no connection was made"

// Precheck refuses a target with no usable host-key pin, so the worker
// reports HostKeyNotPinned without revealing the credential or contacting
// the target.
func (a *sshAdapter) Precheck(c Conn) (Result, string, bool) {
	if pins, _ := parsePins(c.HostKeys); len(pins) == 0 {
		return HostKeyNotPinned, NotPinnedDetail, true
	}
	return Valid, "", false
}

// Validate signs in to c as cred.Username and closes the connection once
// authentication completes. A successful sign-in => Valid; an auth
// rejection by a reachable target => Invalid; a target with no usable pin in
// c.HostKeys => HostKeyNotPinned, without dialing; a host key matching none
// of them => HostKeyMismatch, with the presented and pinned SHA256
// fingerprints in the detail; a credential that can't be used or a
// dial/handshake transport error => Unreachable. The host key is checked
// during key exchange, before any credential is offered.
func (a *sshAdapter) Validate(ctx context.Context, c Conn, cred Cred) (Result, string) {
	auth, method, err := sshAuth(cred)
	if err != nil {
		return Unreachable, err.Error()
	}
	pins, pinAlgos := parsePins(c.HostKeys)
	if len(pins) == 0 {
		return HostKeyNotPinned, NotPinnedDetail
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dialTimeout) // dialTimeout defined in ldap.go
	}
	var presented string
	cfg := &ssh.ClientConfig{
		User:              cred.Username,
		Auth:              auth,
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
	_ = conn.SetDeadline(deadline)

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		switch {
		case errors.Is(err, errHostKeyMismatch):
			return HostKeyMismatch, fmt.Sprintf("%v (presented %s, pinned %s)", errHostKeyMismatch, presented, strings.Join(pinFingerprints(pins), ", "))
		}
		// A reachable target that rejects the credential surfaces as an auth
		// failure during the handshake; treat that as Invalid, everything
		// else as Unreachable. x/crypto/ssh wraps auth failures with this
		// prefix.
		if isAuthFailure(err) {
			return Invalid, method + " authentication rejected"
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

// sshAuth picks how to sign in from what the secret holds: its private key
// when it has one, otherwise its password (offered as password and as
// keyboard-interactive, which many servers use for passwords).
func sshAuth(cred Cred) ([]ssh.AuthMethod, string, error) {
	if cred.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if cred.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.PrivateKey), []byte(cred.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cred.PrivateKey))
		}
		if err != nil {
			return nil, "", fmt.Errorf("parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, "public-key", nil
	}
	if cred.Password != "" {
		pw := cred.Password
		answer := func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = pw
			}
			return answers, nil
		}
		return []ssh.AuthMethod{ssh.Password(pw), ssh.KeyboardInteractive(answer)}, "password", nil
	}
	return nil, "", errors.New("the secret has no private key or password to sign in with")
}

// pinFingerprints lists the pins' SHA256 fingerprints.
func pinFingerprints(pins []ssh.PublicKey) []string {
	out := make([]string, len(pins))
	for i, p := range pins {
		out[i] = ssh.FingerprintSHA256(p)
	}
	return out
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

// errHostKeyMismatch is the host-key refusal, worded as the SSH broker words
// it.
var errHostKeyMismatch = errors.New("host key mismatch")

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
		got := key.Marshal()
		for _, p := range pins {
			if bytes.Equal(p.Marshal(), got) {
				return nil
			}
		}
		return errHostKeyMismatch
	}
}
