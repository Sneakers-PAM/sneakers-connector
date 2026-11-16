// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	"github.com/Sneakers-PAM/sneakers-connector/internal/mtlstest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// pingService is a stand-in for a data service on the main port.
var pingService = grpc.ServiceDesc{
	ServiceName: "test.Ping",
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Ping",
		Handler: func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
			return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
		},
	}},
}

type mtlsServer struct {
	mainAddr, healthAddr string
	stop                 func() error
}

// startMTLSServer runs RunWithHealthPort on two fresh loopback ports. A port
// another test took in between is retried on fresh ones, and a server that
// exits early fails the test with its own error.
func startMTLSServer(t *testing.T, serverFiles mtls.Files) *mtlsServer {
	t.Helper()
	p, err := mtls.NewProvider(serverFiles)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		mainPort, healthPort := freePort(t), freePort(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- RunWithHealthPort(ctx, mainPort, healthPort, log.Nop(), nil, func(gs *grpc.Server) {
				gs.RegisterService(&pingService, struct{}{})
			}, p.ServerOption())
		}()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) && !ready {
			select {
			case err := <-done:
				lastErr = err
				cancel()
				goto retry
			default:
			}
			c1, e1 := net.DialTimeout("tcp", "127.0.0.1:"+mainPort, 100*time.Millisecond)
			c2, e2 := net.DialTimeout("tcp", "127.0.0.1:"+healthPort, 100*time.Millisecond)
			if e1 == nil {
				_ = c1.Close()
			}
			if e2 == nil {
				_ = c2.Close()
			}
			ready = e1 == nil && e2 == nil
			if !ready {
				time.Sleep(20 * time.Millisecond)
			}
		}
		if ready {
			s := &mtlsServer{mainAddr: "127.0.0.1:" + mainPort, healthAddr: "127.0.0.1:" + healthPort}
			var once sync.Once
			var stopErr error
			s.stop = func() error {
				once.Do(func() {
					cancel()
					select {
					case stopErr = <-done:
					case <-time.After(10 * time.Second):
						t.Error("server did not stop")
					}
				})
				return stopErr
			}
			t.Cleanup(func() { _ = s.stop() })
			return s
		}
		cancel()
		lastErr = context.DeadlineExceeded
	retry:
	}
	t.Fatalf("server did not start: %v", lastErr)
	return nil
}

func checkHealth(ctx context.Context, cc *grpc.ClientConn) error {
	_, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func TestMainPortRequiresAClientCertificate(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	s := startMTLSServer(t, ca.Issue(t, "sneakers-connector"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Plaintext is refused.
	plain, err := grpc.NewClient(s.mainAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if err := checkHealth(ctx, plain); err == nil {
		t.Fatal("plaintext call to the mTLS port succeeded")
	}

	// A certificate from another CA is refused.
	other := mtlstest.NewCA(t, "another-ca")
	op, err := mtls.NewProvider(mtlstest.Trusting(t, other.Issue(t, "intruder"), ca))
	if err != nil {
		t.Fatal(err)
	}
	oc, err := grpc.NewClient(s.mainAddr, op.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = oc.Close() }()
	if err := checkHealth(ctx, oc); err == nil {
		t.Fatal("a client certificate from another CA was accepted")
	}

	// A certificate signed by the cluster CA is accepted.
	gp, err := mtls.NewProvider(ca.Issue(t, "sneakers-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	gc, err := grpc.NewClient(s.mainAddr, gp.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gc.Close() }()
	if err := checkHealth(ctx, gc); err != nil {
		t.Fatalf("a client with a certificate from the cluster CA was refused: %v", err)
	}
}

func TestHealthPortIsPlainAndServesOnlyHealth(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	s := startMTLSServer(t, ca.Issue(t, "sneakers-connector"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cc, err := grpc.NewClient(s.healthAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	if err := checkHealth(ctx, cc); err != nil {
		t.Fatalf("plain health check on the health port: %v", err)
	}
	r, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{Service: LivenessService})
	if err != nil || r.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness on the health port = %v, %v", r.GetStatus(), err)
	}

	// A service registered on the main port is not reachable here.
	var out healthpb.HealthCheckResponse
	err = cc.Invoke(ctx, "/test.Ping/Ping", &healthpb.HealthCheckRequest{}, &out)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("data service on the health port: code = %v (%v), want Unimplemented", status.Code(err), err)
	}
	// Nor is reflection, which would list the data services.
	rs, err := cc.NewStream(ctx, &grpc.StreamDesc{StreamName: "ServerReflectionInfo", ServerStreams: true, ClientStreams: true}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
	if err == nil {
		err = rs.RecvMsg(&healthpb.HealthCheckResponse{})
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("reflection on the health port: code = %v (%v), want Unimplemented", status.Code(err), err)
	}

	// The same call over mTLS on the main port does work.
	gp, err := mtls.NewProvider(ca.Issue(t, "sneakers-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	mc, err := grpc.NewClient(s.mainAddr, gp.DialOption())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mc.Close() }()
	if err := mc.Invoke(ctx, "/test.Ping/Ping", &healthpb.HealthCheckRequest{}, &out); err != nil {
		t.Fatalf("data service on the main port: %v", err)
	}
}

func TestShutdownStopsBothPorts(t *testing.T) {
	ca := mtlstest.NewCA(t, "sneakers-test-ca")
	s := startMTLSServer(t, ca.Issue(t, "sneakers-connector"))
	if err := s.stop(); err != nil {
		t.Fatalf("server returned %v on shutdown", err)
	}
	for _, addr := range []string{s.mainAddr, s.healthAddr} {
		if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("%s still accepting after shutdown", addr)
		}
	}
}
