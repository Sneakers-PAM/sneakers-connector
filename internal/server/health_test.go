// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// testTTL is the cache window the tests run with; waiting it out lets the next
// check run again.
const testTTL = time.Second

func newTestChecker(t *testing.T, deps ...health.Dependency) *health.Checker {
	t.Helper()
	c, err := NewChecker(log.Nop(), deps, health.WithTTL(testTTL))
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	return c
}

// healthClient runs a server with checker and returns a health client on it.
func healthClient(t *testing.T, checker *health.Checker) healthpb.HealthClient {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, log.Nop(), checker, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if checker != nil {
		awaitFirstPass(t, checker)
	}
	return healthpb.NewHealthClient(conn)
}

func check(t *testing.T, c healthpb.HealthClient, service string) (healthpb.HealthCheckResponse_ServingStatus, metadata.MD) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var md metadata.MD
	resp, err := c.Check(ctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&md), grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("check %q: %v", service, err)
	}
	return resp.GetStatus(), md
}

func TestHealth_ReadinessFollowsVaultLivenessDoesNot(t *testing.T) {
	var down atomic.Bool
	checker := newTestChecker(t, health.Dependency{Name: "vault", Required: true, Check: func(context.Context) error {
		if down.Load() {
			return errors.New("dial tcp vault.example.test:9091: secret-token-text")
		}
		return nil
	}})
	c := healthClient(t, checker)

	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness while healthy = %v", st)
	}
	down.Store(true)
	time.Sleep(2 * testTTL)
	st, md := check(t, c, "")
	if st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness while the vault is down = %v, want NOT_SERVING", st)
	}
	if st, _ := check(t, c, "liveness"); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness while the vault is down = %v, want SERVING", st)
	}

	raw := md.Get(HeaderHealth)
	if len(raw) != 1 {
		t.Fatalf("%s = %v, want one value", HeaderHealth, raw)
	}
	var body struct {
		Status       string
		Dependencies []struct {
			Name, State, Error, CheckedAt, Version string
			Required                               bool
		}
	}
	if err := json.Unmarshal([]byte(raw[0]), &body); err != nil {
		t.Fatalf("%s is not JSON: %v (%s)", HeaderHealth, err, raw[0])
	}
	d := body.Dependencies
	if body.Status != "down" || len(d) != 1 || d[0].Name != "vault" || d[0].State != "down" || !d[0].Required ||
		d[0].Error != "error" || d[0].Version != "" || d[0].CheckedAt == "" {
		t.Fatalf("health body = %s", raw[0])
	}
	for _, bad := range []string{"secret-token-text", "vault.example.test"} {
		if contains(raw[0], bad) {
			t.Fatalf("health body carries %q: %s", bad, raw[0])
		}
	}
	if v := md.Get("sneakers-version"); len(v) != 1 {
		t.Fatalf("the version header is gone: %v", md)
	}

	down.Store(false)
	time.Sleep(2 * testTTL)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness after recovery = %v, want SERVING", st)
	}
}

func TestHealth_LivenessCarriesNoHealthBody(t *testing.T) {
	c := healthClient(t, newTestChecker(t))
	if _, md := check(t, c, "liveness"); len(md.Get(HeaderHealth)) != 0 {
		t.Fatalf("liveness carried %v", md.Get(HeaderHealth))
	}
}

func TestHealth_UnknownServiceAndWatch(t *testing.T) {
	c := healthClient(t, newTestChecker(t))
	check(t, c, "") // wait for the server
	_, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown service: %v, want NotFound", err)
	}
	w, err := c.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if resp, err := w.Recv(); err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("watch: %v %v, want SERVING", resp.GetStatus(), err)
	}
}

func TestHealth_NilCheckerIsAlwaysReady(t *testing.T) {
	c := healthClient(t, nil)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness without a checker = %v", st)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
