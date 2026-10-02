// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshAdapter validates an SSH private key by opening a public-key-authenticated
// connection to the target as the account. It never executes a command and
// never logs key material. Rotation (two-phase authorized_keys swap) is not
// implemented; ssh secrets are heartbeat-only for now.
type sshAdapter struct{}

func init() { Register("ssh", &sshAdapter{}) }

// Validate parses cred's private key and attempts a public-key SSH handshake
// to c as cred.Username. A successful handshake => Valid; an auth rejection by
// a reachable target => Invalid; a parse failure or dial/handshake transport
// error => Unreachable.
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
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- validation only, no command runs; TODO: pin host keys (known_hosts) before production use
		Timeout:         time.Until(deadline),
	}

	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	conn, err := net.DialTimeout("tcp", addr, time.Until(deadline))
	if err != nil {
		return Unreachable, fmt.Sprintf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
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
