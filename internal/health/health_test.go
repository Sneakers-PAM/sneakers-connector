// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// toggle is a dependency that fails while down is set.
type toggle struct {
	down  atomic.Bool
	err   error
	calls atomic.Int32
}

func (d *toggle) check(context.Context) error {
	d.calls.Add(1)
	if d.down.Load() {
		return d.err
	}
	return nil
}

func newChecker(clk *clock, deps ...Dep) *Checker {
	c := New(log.Nop(), deps...)
	c.now = clk.now
	return c
}

func TestReport_RequiredDownThenRecovers(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	vault := &toggle{err: errors.New("dial tcp vault.example.test:9091: connect: refused token=hunter2")}
	c := newChecker(clk, Dep{Name: "vault", Required: true, Check: vault.check})

	if r := c.Report(context.Background()); r.Status != StateOK || r.Dependencies[0].State != StateOK {
		t.Fatalf("healthy: %+v", r)
	}
	vault.down.Store(true)
	clk.advance(CacheTTL)
	r := c.Report(context.Background())
	if r.Status != StateDown || r.Dependencies[0].State != StateDown || !r.Dependencies[0].Required {
		t.Fatalf("down: %+v", r)
	}
	if r.Dependencies[0].Error != ClassError {
		t.Fatalf("error class = %q, want %q", r.Dependencies[0].Error, ClassError)
	}
	if r.Dependencies[0].CheckedAt != "2026-10-05T12:00:05Z" {
		t.Fatalf("checkedAt = %q", r.Dependencies[0].CheckedAt)
	}
	vault.down.Store(false)
	if r := c.Report(context.Background()); r.Status != StateDown {
		t.Fatalf("inside the cache window the down result stands: %+v", r)
	}
	clk.advance(CacheTTL)
	if r := c.Report(context.Background()); r.Status != StateOK || r.Dependencies[0].Error != "" {
		t.Fatalf("recovered: %+v", r)
	}
}

func TestReport_CachedWithinTheWindow(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	vault := &toggle{}
	c := newChecker(clk, Dep{Name: "vault", Required: true, Check: vault.check})
	for range 5 {
		c.Report(context.Background())
		clk.advance(CacheTTL / 10)
	}
	if n := vault.calls.Load(); n != 1 {
		t.Fatalf("checked %d times within the cache window, want 1", n)
	}
}

func TestReport_ConcurrentCallersShareOneRun(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	var calls atomic.Int32
	slow := func(ctx context.Context) error {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return nil
	}
	c := newChecker(clk, Dep{Name: "vault", Required: true, Check: slow})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { c.Report(context.Background()) })
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d runs for 10 concurrent callers, want 1", n)
	}
}

func TestReport_OptionalFailingIsDegraded(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	peer := &toggle{err: status.Error(codes.Unavailable, "no route")}
	peer.down.Store(true)
	c := newChecker(clk,
		Dep{Name: "vault", Required: true, Check: func(context.Context) error { return nil }},
		Dep{Name: "peer", Check: peer.check},
	)
	r := c.Report(context.Background())
	if r.Status != StateDegraded || r.Dependencies[1].State != StateDegraded || r.Dependencies[1].Error != ClassUnavailable {
		t.Fatalf("degraded: %+v", r)
	}
}

func TestReport_ChecksTimeOut(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	hang := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	c := newChecker(clk, Dep{Name: "vault", Required: true, Check: hang})
	start := time.Now()
	r := c.Report(context.Background())
	if time.Since(start) > CheckTimeout+500*time.Millisecond {
		t.Fatalf("report took %v, want about %v", time.Since(start), CheckTimeout)
	}
	if r.Status != StateDown || r.Dependencies[0].Error != ClassTimeout {
		t.Fatalf("timeout: %+v", r)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"nil":         {nil, ""},
		"deadline":    {fmt.Errorf("ping: %w", context.DeadlineExceeded), ClassTimeout},
		"refused":     {&net.OpError{Op: "dial", Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED)}, ClassRefused},
		"network":     {&net.OpError{Op: "read", Err: errors.New("connection reset")}, ClassUnavailable},
		"unavailable": {status.Error(codes.Unavailable, "down"), ClassUnavailable},
		"unauth":      {status.Error(codes.Unauthenticated, "no"), ClassUnauthenticated},
		"denied":      {status.Error(codes.PermissionDenied, "no"), ClassUnauthenticated},
		"other":       {errors.New("syntax error at or near SELECT"), ClassError},
	}
	for name, tc := range cases {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("%s: Classify = %q, want %q", name, got, tc.want)
		}
	}
}

func TestReport_NeverCarriesTheErrorText(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	c := newChecker(clk, Dep{Name: "vault", Required: true, Check: func(context.Context) error {
		return errors.New("rpc error: token hunter2 rejected by vault.example.test")
	}})
	r := c.Report(context.Background())
	got := fmt.Sprintf("%+v", r)
	for _, bad := range []string{"hunter2", "vault.example.test", "token"} {
		if strings.Contains(got, bad) {
			t.Fatalf("report carries %q: %s", bad, got)
		}
	}
}

type fakeHealth struct {
	resp *healthpb.HealthCheckResponse
	err  error
}

func (f fakeHealth) Check(context.Context, *healthpb.HealthCheckRequest, ...grpc.CallOption) (*healthpb.HealthCheckResponse, error) {
	return f.resp, f.err
}

func TestGRPCPeer(t *testing.T) {
	serving := fakeHealth{resp: &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}}
	if err := GRPCPeer(serving)(context.Background()); err != nil {
		t.Fatalf("serving peer: %v", err)
	}
	notServing := fakeHealth{resp: &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}}
	if got := Classify(GRPCPeer(notServing)(context.Background())); got != ClassUnavailable {
		t.Fatalf("not-serving peer class = %q, want %q", got, ClassUnavailable)
	}
	failing := fakeHealth{err: status.Error(codes.Unavailable, "connection refused")}
	if got := Classify(GRPCPeer(failing)(context.Background())); got != ClassUnavailable {
		t.Fatalf("unreachable peer class = %q, want %q", got, ClassUnavailable)
	}
}
