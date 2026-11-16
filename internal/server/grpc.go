// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package server provides a Run helper that boots a gRPC server with the
// standard health + reflection services and graceful shutdown on context
// cancellation.
package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// gracefulStopTimeout bounds how long Run will wait for in-flight RPCs to
// drain before forcibly stopping the server. Without it, a hung peer could
// keep GracefulStop blocked indefinitely.
const gracefulStopTimeout = 10 * time.Second

// Run boots a gRPC server listening on :port, registers the health (always
// ready; see RunWithHealth) and reflection services, calls register to attach caller-owned services, then
// serves until ctx is cancelled. On cancellation it performs a graceful stop
// and returns nil. A non-nil error indicates a fatal startup or serve failure.
//
// Optional grpc.ServerOptions (e.g. interceptors) are passed through to
// grpc.NewServer; callers that pass none get the previous behaviour.
func Run(ctx context.Context, port string, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithLogger(ctx, port, log.Nop(), register, opts...)
}

// RunWithLogger is Run with lg logging the panics the recovery interceptors
// catch. Run itself discards them.
func RunWithLogger(ctx context.Context, port string, lg log.Logger, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealth(ctx, port, lg, nil, register, opts...)
}

// RunWithHealth is RunWithLogger with checker deciding readiness: the health
// check's service "" answers NOT_SERVING while a required dependency is down.
// Service "liveness" always answers SERVING. A nil checker is always ready.
func RunWithHealth(ctx context.Context, port string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealthPort(ctx, port, "", lg, checker, register, opts...)
}

// RunWithHealthPort is RunWithHealth that also serves a plain, health-only
// gRPC port when healthPort is not empty. The kubelet's gRPC probe cannot
// present a client certificate, so with mutual TLS on the main port (opts
// carries the TLS credentials) the probe uses this one. It registers the
// standard health service only: no reflection, none of register's services,
// and none of the caller's opts (so no TLS and no caller authentication on
// it). Both ports share one readiness answer and stop together.
func RunWithHealthPort(ctx context.Context, port, healthPort string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	hs, bi, err := newHealth(checker)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	var healthLis net.Listener
	if healthPort != "" {
		if healthLis, err = net.Listen("tcp", ":"+healthPort); err != nil {
			_ = lis.Close()
			return fmt.Errorf("listen health port: %w", err)
		}
	}

	// Build the default ServerOptions, prepended before caller-supplied opts.
	//
	//   - StatsHandler(otelgrpc): traces every service by default. Prepended so
	//     a caller StatsHandler (gRPC applies the last one) can still override.
	//   - ChainUnaryInterceptor(recovery) / StreamInterceptor(recovery): make
	//     panic recovery the OUTERMOST interceptor. grpc.ChainUnaryInterceptor
	//     is additive across ServerOptions (v1.81.x appends, no "last wins"),
	//     and the chain executes first-added-outermost. Prepending our
	//     ChainUnaryInterceptor before caller opts means recovery runs before
	//     any caller-supplied interceptor (e.g. an auth interceptor) and before the
	//     handler, so it catches panics from all of them. The otelgrpc
	//     StatsHandler still creates the server span first, so the recovery
	//     interceptor can record the panic on a live span.
	//
	// ChainStreamInterceptor is additive (like the unary chain), so a caller
	// that later supplies its own stream interceptor composes with recovery
	// rather than panicking (plain grpc.StreamInterceptor allows only one and
	// panics on a second).
	defaults := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(lg), bi.UnaryServerInterceptor(), reportUnaryInterceptor(checker)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(lg), bi.StreamServerInterceptor()),
	}
	healthOpts := append([]grpc.ServerOption(nil), defaults...)
	opts = append(defaults, opts...)

	s := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(s, hs)
	reflection.Register(s)
	if register != nil {
		register(s)
	}

	biCtx, stopBI := context.WithCancel(ctx)
	defer stopBI()
	go bi.Run(biCtx)
	if checker != nil {
		go checker.Run(biCtx)
	}

	servers := []*grpc.Server{s}
	errCh := make(chan error, 2)
	go serveOn(s, lis, errCh)
	if healthLis != nil {
		hsrv := grpc.NewServer(healthOpts...)
		healthpb.RegisterHealthServer(hsrv, hs)
		servers = append(servers, hsrv)
		lg.Info("serving plain health-only port", log.F("port", healthPort))
		go serveOn(hsrv, healthLis, errCh)
	}

	select {
	case <-ctx.Done():
		hs.Shutdown()
		stopServers(servers, errCh)
		return nil
	case err := <-errCh:
		// One listener failed: stop the other and report the failure.
		for _, srv := range servers {
			srv.Stop()
		}
		return err
	}
}

// serveOn serves srv on lis and sends the outcome (nil after a stop) to errCh.
func serveOn(srv *grpc.Server, lis net.Listener, errCh chan<- error) {
	if err := srv.Serve(lis); err != nil {
		errCh <- err
		return
	}
	errCh <- nil
}

// stopServers stops every server gracefully, forcing the stop after
// gracefulStopTimeout, then collects each Serve's outcome from errCh.
func stopServers(servers []*grpc.Server, errCh <-chan error) {
	stopped := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, srv := range servers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				srv.GracefulStop()
			}()
		}
		wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(gracefulStopTimeout):
		for _, srv := range servers {
			srv.Stop()
		}
	}
	for range servers {
		<-errCh
	}
}

// ClientStatsHandler returns the grpc.DialOption that installs the OpenTelemetry
// client stats handler on an outbound gRPC connection, so trace context is
// injected into outgoing RPC metadata and client spans are recorded.
//
//	conn, err := grpc.NewClient(target, server.ClientStatsHandler(), ...)
func ClientStatsHandler() grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler())
}
