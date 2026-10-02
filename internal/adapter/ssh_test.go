// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer starts a minimal ssh server that accepts only authorizedPub.
// It returns the listen host/port and a stop func. Synthetic keys only.
func startTestSSHServer(t *testing.T, authorizedPub ssh.PublicKey) (host string, port int, stop func()) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) == string(authorizedPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errAuth
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

var errAuth = &sshAuthError{}

type sshAuthError struct{}

func (*sshAuthError) Error() string { return "unauthorized key" }

// genClientKey returns a synthetic ed25519 private key (OpenSSH PEM) and its ssh.PublicKey.
func genClientKey(t *testing.T) (pemPriv string, pub ssh.PublicKey) {
	t.Helper()
	pub25519, priv25519, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv25519, "")
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub25519)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

func TestSSHValidateSucceedsWithAuthorizedKey(t *testing.T) {
	pemPriv, pub := genClientKey(t)
	host, port, stop := startTestSSHServer(t, pub)
	defer stop()

	a, ok := Get("ssh")
	if !ok {
		t.Fatal("ssh adapter not registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, detail := a.Validate(ctx, Conn{Host: host, Port: port}, Cred{Username: "svc", PrivateKey: pemPriv})
	if res != Valid {
		t.Fatalf("Validate = %v (%s), want Valid", res, detail)
	}
}

func TestSSHValidateRejectsWrongKey(t *testing.T) {
	_, authPub := genClientKey(t)
	otherPem, _ := genClientKey(t) // a different, unauthorized key
	host, port, stop := startTestSSHServer(t, authPub)
	defer stop()

	a, _ := Get("ssh")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, _ := a.Validate(ctx, Conn{Host: host, Port: port}, Cred{Username: "svc", PrivateKey: otherPem})
	if res != Invalid {
		t.Fatalf("Validate with wrong key = %v, want Invalid", res)
	}
}

func TestSSHValidateUnreachableOnBadKey(t *testing.T) {
	a, _ := Get("ssh")
	res, _ := a.Validate(context.Background(), Conn{Host: "127.0.0.1", Port: 1}, Cred{Username: "svc", PrivateKey: "not-a-key"})
	if res != Unreachable {
		t.Fatalf("Validate with garbage key = %v, want Unreachable", res)
	}
}

func TestSSHRotateNotImplemented(t *testing.T) {
	a, _ := Get("ssh")
	res, detail := a.Rotate(context.Background(), Conn{Host: "127.0.0.1", Port: 22}, Cred{Username: "svc"}, "new")
	if res != Unreachable || detail == "" {
		t.Fatalf("Rotate = %v %q, want Unreachable with a not-implemented message", res, detail)
	}
}
