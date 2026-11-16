// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"context"
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/mtlstest"
	"google.golang.org/grpc"
)

// startMTLSVault serves claimVault over mutual TLS with the given files.
func startMTLSVault(t *testing.T, files mtls.Files) string {
	t.Helper()
	p, err := mtls.NewProvider(files)
	if err != nil {
		t.Fatalf("server provider: %v", err)
	}
	gs := grpc.NewServer(p.ServerOption())
	vaultv1.RegisterVaultServiceServer(gs, claimVault{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

func claim(t *testing.T, c *Client) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{})
	return err
}

func TestDialPresentsItsCertificateToAnMTLSVault(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	addr := startMTLSVault(t, ca.Issue(t, "sneakers-vault"))

	cp, err := mtls.NewProvider(ca.Issue(t, "sneakers-connector"))
	if err != nil {
		t.Fatalf("client provider: %v", err)
	}
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}), log.Nop(), cp.DialOption())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := claim(t, c); err != nil {
		t.Fatalf("call over mTLS: %v", err)
	}
}

func TestDialWithoutMTLSIsRefusedByAnMTLSVault(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	addr := startMTLSVault(t, ca.Issue(t, "sneakers-vault"))

	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}), log.Nop())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := claim(t, c); err == nil {
		t.Fatal("a plaintext call to an mTLS vault succeeded")
	}
}

func TestDialRefusesAVaultSignedByAnotherCA(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	rogue := mtlstest.NewCA(t, "rogue-ca")
	addr := startMTLSVault(t, mtlstest.Trusting(t, rogue.Issue(t, "sneakers-vault"), ca))

	cp, err := mtls.NewProvider(ca.Issue(t, "sneakers-connector"))
	if err != nil {
		t.Fatalf("client provider: %v", err)
	}
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}), log.Nop(), cp.DialOption())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := claim(t, c); err == nil {
		t.Fatal("the connector trusted a vault certificate from another CA")
	}
}
