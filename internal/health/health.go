// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package health checks the service's dependencies for its readiness. Each
// dependency is pinged with a short timeout and the results are cached for a
// few seconds, so frequent probes don't load the dependencies. A required
// dependency that fails makes the service not ready (down); an optional one
// only marks it degraded. Liveness never asks this package.
package health

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

const (
	// CacheTTL is how long a round of checks answers readiness.
	CacheTTL = 5 * time.Second
	// CheckTimeout bounds each dependency's ping.
	CheckTimeout = time.Second
)

// The states of a dependency and of the service as a whole.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
)

// The error classes a failed check reports. They stand in for the error
// itself, which can carry a DSN, an address or a credential.
const (
	ClassTimeout         = "timeout"
	ClassRefused         = "refused"
	ClassUnavailable     = "unavailable"
	ClassUnauthenticated = "unauthenticated"
	ClassError           = "error"
)

// Dep is one dependency: Check returns nil while it's usable.
type Dep struct {
	Name     string
	Required bool
	Check    func(context.Context) error
}

// DepState is a dependency's last check. Version is filled in by the caller
// that knows it (the recorded sneakers-dep-* versions).
type DepState struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Required  bool   `json:"required"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checkedAt"`
	Version   string `json:"version,omitempty"`
}

// Report is the service's readiness: down when a required dependency is
// down, degraded when an optional one is, else ok.
type Report struct {
	Status       string     `json:"status"`
	Dependencies []DepState `json:"dependencies"`
}

// Checker runs the dependency checks and caches their results.
type Checker struct {
	deps []Dep
	log  log.Logger
	now  func() time.Time

	mu     sync.Mutex
	last   Report
	at     time.Time
	cached bool
}

// New returns a Checker for deps. lg gets a line each time a dependency's
// state changes.
func New(lg log.Logger, deps ...Dep) *Checker {
	if lg == nil {
		lg = log.Nop()
	}
	return &Checker{deps: deps, log: lg, now: time.Now}
}

// WithClock replaces the clock the cache window is measured on (tests).
func (c *Checker) WithClock(now func() time.Time) *Checker {
	c.now = now
	return c
}

// Report returns the readiness, running the checks when the cached round is
// older than CacheTTL. Concurrent callers wait for one round.
func (c *Checker) Report(ctx context.Context) Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cached && now.Sub(c.at) < CacheTTL {
		return c.last
	}
	r := c.run(context.WithoutCancel(ctx), now)
	c.logChanges(ctx, r)
	c.last, c.at, c.cached = r, now, true
	return r
}

func (c *Checker) run(ctx context.Context, now time.Time) Report {
	r := Report{Status: StateOK, Dependencies: make([]DepState, len(c.deps))}
	var wg sync.WaitGroup
	for i, d := range c.deps {
		wg.Go(func() {
			cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
			defer cancel()
			s := DepState{Name: d.Name, Required: d.Required, State: StateOK, CheckedAt: now.UTC().Format(time.RFC3339)}
			if err := d.Check(cctx); err != nil {
				s.Error = Classify(err)
				s.State = StateDegraded
				if d.Required {
					s.State = StateDown
				}
			}
			r.Dependencies[i] = s
		})
	}
	wg.Wait()
	for _, s := range r.Dependencies {
		switch {
		case s.State == StateDown:
			r.Status = StateDown
		case s.State == StateDegraded && r.Status == StateOK:
			r.Status = StateDegraded
		}
	}
	return r
}

func (c *Checker) logChanges(ctx context.Context, r Report) {
	prev := map[string]string{}
	for _, s := range c.last.Dependencies {
		prev[s.Name] = s.State
	}
	lg := c.log.Ctx(ctx)
	for _, s := range r.Dependencies {
		was, seen := prev[s.Name]
		if seen && was == s.State || !seen && s.State == StateOK {
			continue
		}
		fields := []log.Field{log.F("dependency", s.Name), log.F("required", s.Required), log.F("error_class", s.Error)}
		if s.State == StateOK {
			lg.Info("health: dependency recovered", fields...)
		} else {
			lg.Warn("health: dependency "+s.State, fields...)
		}
	}
}

// Classify maps a check's error to its class.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ClassRefused
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable:
			return ClassUnavailable
		case codes.Unauthenticated, codes.PermissionDenied:
			return ClassUnauthenticated
		case codes.DeadlineExceeded:
			return ClassTimeout
		}
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return ClassTimeout
		}
		return ClassUnavailable
	}
	return ClassError
}

// HealthChecker is the Check half of a grpc.health.v1 client.
type HealthChecker interface {
	Check(ctx context.Context, in *healthpb.HealthCheckRequest, opts ...grpc.CallOption) (*healthpb.HealthCheckResponse, error)
}

// GRPCPeer checks a gRPC peer through its standard health check (readiness,
// service ""). A peer that answers anything but SERVING is unavailable.
func GRPCPeer(hc HealthChecker) func(context.Context) error {
	return func(ctx context.Context) error {
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return status.Error(codes.Unavailable, "peer not serving")
		}
		return nil
	}
}

// Vault is the required vault dependency, checked through the vault's own
// readiness on the connection the worker already uses. The connector's only
// work is the heartbeat jobs it claims from the vault and reports back to it,
// so without the vault it can do nothing. The health check needs no token.
func Vault(conn grpc.ClientConnInterface) Dep {
	return Dep{Name: "vault", Required: true, Check: GRPCPeer(healthpb.NewHealthClient(conn))}
}
