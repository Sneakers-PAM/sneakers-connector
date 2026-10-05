// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-connector/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// startVault runs a stand-in vault (a real gRPC server with the stock health
// service) on addr and returns a stop func.
func startVault(t *testing.T, addr string) (*grpchealth.Server, func()) {
	t.Helper()
	var lis net.Listener
	var err error
	for range 50 { // the port can take a moment to free after a stop
		if lis, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	s := grpc.NewServer()
	hs := grpchealth.NewServer()
	healthpb.RegisterHealthServer(s, hs)
	go func() { _ = s.Serve(lis) }()
	return hs, s.Stop
}

// The vault goes away mid-test: readiness fails, liveness stays up, and
// readiness recovers on its own once the vault is back and the cache window
// has passed.
func TestHealth_VaultStoppedMidTest(t *testing.T) {
	addr := "127.0.0.1:" + freePort(t)
	vaultHealth, stop := startVault(t, addr)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial vault: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	clk := &testClock{t: time.Now()}
	checker := health.New(log.Nop(), health.Vault(conn)).WithClock(clk.now)
	c := healthClient(t, checker)

	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness with the vault up = %v", st)
	}

	vaultHealth.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	clk.advance(health.CacheTTL)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness with the vault not serving = %v, want NOT_SERVING", st)
	}

	stop()
	clk.advance(health.CacheTTL)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness with the vault stopped = %v, want NOT_SERVING", st)
	}
	if st, _ := check(t, c, "liveness"); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness with the vault stopped = %v, want SERVING", st)
	}

	_, stop = startVault(t, addr)
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		clk.advance(health.CacheTTL)
		st, _ := check(t, c, "")
		if st == healthpb.HealthCheckResponse_SERVING {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness never recovered after the vault came back: %v", st)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
