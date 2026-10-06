// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// mdVault answers Unimplemented to everything and records the incoming
// metadata of every call, by method.
type mdVault struct {
	mu    sync.Mutex
	calls map[string]metadata.MD
}

func startMDVault(t *testing.T) (string, *mdVault) {
	t.Helper()
	rec := &mdVault{calls: map[string]metadata.MD{}}
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		rec.mu.Lock()
		rec.calls[info.FullMethod] = md
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

func stampBuild(t *testing.T, version, commit string) {
	t.Helper()
	v, c := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = version, commit
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = v, c })
}

func TestDialSendsTheBuildOnEveryPullCall(t *testing.T) {
	stampBuild(t, "v0.9.1", "0123456789abcdef0123456789abcdef01234567")
	addr, rec := startMDVault(t)
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{})
	_, _ = c.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{})
	_, _ = c.ReportHeartbeat(ctx, &vaultv1.ReportHeartbeatRequest{})

	for _, m := range []string{
		vaultv1.VaultService_ClaimDueHeartbeats_FullMethodName,
		vaultv1.VaultService_ClaimDueRotations_FullMethodName,
		vaultv1.VaultService_ReportHeartbeat_FullMethodName,
	} {
		md, ok := rec.calls[m]
		if !ok {
			t.Fatalf("%s: no call reached the vault", m)
		}
		if got := md.Get(MDVersion); len(got) != 1 || got[0] != "v0.9.1" {
			t.Errorf("%s: %s = %q, want [v0.9.1]", m, MDVersion, got)
		}
		if got := md.Get(MDCommit); len(got) != 1 || got[0] != "0123456789abcdef0123456789abcdef01234567" {
			t.Errorf("%s: %s = %q, want the stamped commit", m, MDCommit, got)
		}
	}
}

func TestDialSendsDevAndUnknownForAnUnstampedBuild(t *testing.T) {
	stampBuild(t, "", "")
	addr, rec := startMDVault(t)
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{})

	md := rec.calls[vaultv1.VaultService_ClaimDueHeartbeats_FullMethodName]
	if got := md.Get(MDVersion); len(got) != 1 || got[0] != "dev" {
		t.Errorf("%s = %q, want [dev]", MDVersion, got)
	}
	if got := md.Get(MDCommit); len(got) != 1 || got[0] == "" {
		t.Errorf("%s = %q, want one non-empty value", MDCommit, got)
	}
}
