// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// recordingVault is a vault that answers Unimplemented to everything and
// records the authorization metadata of every call.
type recordingVault struct {
	mu    sync.Mutex
	auths [][]string
}

func (r *recordingVault) last() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.auths[len(r.auths)-1]
}

func startVault(t *testing.T) (addr string, rec *recordingVault) {
	t.Helper()
	rec = &recordingVault{}
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		rec.mu.Lock()
		rec.auths = append(rec.auths, md.Get("authorization"))
		rec.mu.Unlock()
		return h(ctx, req)
	}))
	vaultv1.RegisterVaultServiceServer(gs, vaultv1.UnimplementedVaultServiceServer{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String(), rec
}

func writeToken(t *testing.T, path, tok string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func call(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{})
}

func TestDialSendsWorkloadTokenOnEveryCall(t *testing.T) {
	addr, rec := startVault(t)
	tokFile := filepath.Join(t.TempDir(), "token")
	writeToken(t, tokFile, "token-one")

	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr, EnvWorkloadTokenFile: tokFile}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	call(t, c)
	if got := rec.last(); len(got) != 1 || got[0] != "Bearer token-one" {
		t.Fatalf("authorization = %q, want [Bearer token-one]", got)
	}

	writeToken(t, tokFile, "token-two")
	call(t, c)
	if got := rec.last(); len(got) != 1 || got[0] != "Bearer token-two" {
		t.Fatalf("authorization after rotation = %q, want [Bearer token-two]", got)
	}
}

func TestDialAcceptsConnectorTokenFileAsAlias(t *testing.T) {
	addr, rec := startVault(t)
	tokFile := filepath.Join(t.TempDir(), "token")
	writeToken(t, tokFile, "alias-token")

	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr, EnvConnectorTokenFile: tokFile}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	call(t, c)
	if got := rec.last(); len(got) != 1 || got[0] != "Bearer alias-token" {
		t.Fatalf("authorization = %q, want [Bearer alias-token]", got)
	}
}

func TestDialPrefersWorkloadTokenFileOverAlias(t *testing.T) {
	addr, rec := startVault(t)
	dir := t.TempDir()
	workload, alias := filepath.Join(dir, "workload"), filepath.Join(dir, "alias")
	writeToken(t, workload, "workload-token")
	writeToken(t, alias, "alias-token")

	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr, EnvWorkloadTokenFile: workload, EnvConnectorTokenFile: alias}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	call(t, c)
	if got := rec.last(); len(got) != 1 || got[0] != "Bearer workload-token" {
		t.Fatalf("authorization = %q, want [Bearer workload-token]", got)
	}
}

func TestDialWithoutTokenFileSendsNoAuthorization(t *testing.T) {
	addr, rec := startVault(t)

	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	call(t, c)
	if got := rec.last(); len(got) != 0 {
		t.Fatalf("authorization = %q, want none", got)
	}
}

func TestDialRefusesUnreadableTokenFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := dial(envOf(map[string]string{EnvWorkloadTokenFile: missing})); err == nil {
		t.Fatal("dial with a missing token file succeeded, want an error")
	}
}
