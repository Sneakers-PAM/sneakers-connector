// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newHostSigner returns a fresh ed25519 SSH host key, generated per run.
func newHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	return s
}

// newRSAHostSigner returns a fresh RSA SSH host key, generated per run.
func newRSAHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa host key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("rsa host signer: %v", err)
	}
	return s
}

// pinOf renders a host key as a pin: authorized_keys form, no newline.
func pinOf(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// startKeyedSSHServer starts a minimal SSH server with the given host keys
// that accepts only authorizedPub. It counts every public-key auth attempt,
// so a test can prove the client never offered its key.
func startKeyedSSHServer(t *testing.T, authorizedPub ssh.PublicKey, hostKeys ...ssh.Signer) (host string, port int, authAttempts *atomic.Int32) {
	t.Helper()
	authAttempts = &atomic.Int32{}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			authAttempts.Add(1)
			if string(key.Marshal()) == string(authorizedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuth
		},
	}
	for _, hk := range hostKeys {
		cfg.AddHostKey(hk)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no sessions in test")
				}
				_ = sc.Close()
			}()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, authAttempts
}

func validateSSH(t *testing.T, c Conn, cred Cred) (Result, string) {
	t.Helper()
	a, ok := Get("ssh")
	if !ok {
		t.Fatal("ssh adapter not registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.Validate(ctx, c, cred)
}

func TestSSHValidateAcceptsPinnedHostKey(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, _ := startKeyedSSHServer(t, pub, hostKey)

	pins := []string{pinOf(newHostSigner(t)), pinOf(hostKey) + " app01.example.org"}
	res, detail := validateSSH(t, Conn{Host: host, Port: port, HostKeys: pins}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != Valid {
		t.Fatalf("Validate = %v (%s), want Valid", res, detail)
	}
}

// A host with several host keys is asked for the pinned key's algorithm, so a
// pin on its RSA key verifies even though it would otherwise offer ed25519.
func TestSSHValidateNegotiatesPinnedAlgorithm(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	rsaHost := newRSAHostSigner(t)
	host, port, _ := startKeyedSSHServer(t, pub, newHostSigner(t), rsaHost)

	res, detail := validateSSH(t, Conn{Host: host, Port: port, HostKeys: []string{pinOf(rsaHost)}}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != Valid {
		t.Fatalf("Validate = %v (%s), want Valid", res, detail)
	}
}

func TestSSHValidateRefusesHostKeyMismatch(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, attempts := startKeyedSSHServer(t, pub, hostKey)

	res, detail := validateSSH(t, Conn{Host: host, Port: port, HostKeys: []string{pinOf(newHostSigner(t))}}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != HostKeyMismatch {
		t.Fatalf("Validate = %v (%s), want HostKeyMismatch", res, detail)
	}
	fp := ssh.FingerprintSHA256(hostKey.PublicKey())
	if !strings.Contains(detail, "host key mismatch") || !strings.Contains(detail, fp) {
		t.Fatalf("detail = %q, want the mismatch reason and the presented fingerprint %s", detail, fp)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("client key offered %d times to a host with the wrong key", n)
	}
}

func TestSSHValidateRefusesUnpinnedTarget(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	hostKey := newHostSigner(t)
	host, port, attempts := startKeyedSSHServer(t, pub, hostKey)

	res, detail := validateSSH(t, Conn{Host: host, Port: port}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != HostKeyNotPinned {
		t.Fatalf("Validate = %v (%s), want HostKeyNotPinned", res, detail)
	}
	fp := ssh.FingerprintSHA256(hostKey.PublicKey())
	if !strings.Contains(detail, "host key not pinned for this target") || !strings.Contains(detail, fp) {
		t.Fatalf("detail = %q, want the not-pinned reason and the presented fingerprint %s", detail, fp)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("client key offered %d times to an unpinned host", n)
	}
}

// Pins that don't parse are dropped; with none left the target is unpinned.
func TestSSHValidateTreatsUnparseablePinsAsUnpinned(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, attempts := startKeyedSSHServer(t, pub, newHostSigner(t))

	res, detail := validateSSH(t, Conn{Host: host, Port: port, HostKeys: []string{"not a key"}}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != HostKeyNotPinned {
		t.Fatalf("Validate = %v (%s), want HostKeyNotPinned", res, detail)
	}
	if n := attempts.Load(); n != 0 {
		t.Fatalf("client key offered %d times to an unpinned host", n)
	}
}

func TestHostKeyResultsHaveTheirOwnNames(t *testing.T) {
	if HostKeyNotPinned.String() != "host_key_not_pinned" || HostKeyMismatch.String() != "host_key_mismatch" {
		t.Fatalf("names = %q, %q", HostKeyNotPinned, HostKeyMismatch)
	}
}
