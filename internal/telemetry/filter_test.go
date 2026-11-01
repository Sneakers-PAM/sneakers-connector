// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	commonv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/common/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry/collectortest"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeHealth runs do on each Check, on the service's own server chain.
type fakeHealth struct {
	commonv1.UnimplementedHealthServiceServer
	do func(ctx context.Context) error
}

func (f *fakeHealth) Check(ctx context.Context, _ *commonv1.CheckRequest) (*commonv1.CheckResponse, error) {
	return &commonv1.CheckResponse{}, f.do(ctx)
}

// serve starts the real server with the filters on and returns a plain client
// connection, so only the server's own spans and metrics are exported.
func serve(t *testing.T, c *collectortest.Collector, f *fakeHealth) (*grpc.ClientConn, func()) {
	t.Helper()
	s := telemetry.Settings{Endpoint: c.Endpoint}
	shutdown, err := otel.InitWithOptions(context.Background(), "connector", c.Endpoint, s.Options()...)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(lis.Addr().(*net.TCPAddr).Port)
	if err := lis.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.RunWithLogger(ctx, port, log.Nop(), func(gs *grpc.Server) {
			commonv1.RegisterHealthServiceServer(gs, f)
		})
	}()
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return conn, func() {
		_ = conn.Close()
		cancel()
		<-done
		if err := shutdown(context.Background()); err != nil {
			t.Logf("shutdown: %v", err)
		}
	}
}

// call invokes method once the server is listening, and returns its error.
func call(t *testing.T, ctx context.Context, conn *grpc.ClientConn, method string) error {
	t.Helper()
	var err error
	for range 50 {
		err = conn.Invoke(ctx, method, &commonv1.CheckRequest{}, &commonv1.CheckResponse{})
		if status.Code(err) != codes.Unavailable {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}

const checkMethod = "/sneakers.common.v1.HealthService/Check"

func TestSpansCarryNoErrorText(t *testing.T) {
	tests := []struct {
		name string
		do   func(context.Context) error
	}{
		{"span status", func(context.Context) error { return status.Error(codes.Internal, canary) }},
		{"exception", func(context.Context) error { panic(errors.New(canary)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := collectortest.Start(t, codes.OK)
			conn, stop := serve(t, c, &fakeHealth{do: tt.do})
			if err := call(t, context.Background(), conn, checkMethod); status.Code(err) != codes.Internal {
				t.Fatalf("call: %v", err)
			}
			stop()

			got := c.Text()
			if strings.Contains(got, canary) {
				t.Fatalf("canary exported: %s", got)
			}
			if strings.Contains(got, "\"exception\"") {
				t.Fatalf("exception event exported: %s", got)
			}
			for _, want := range []string{"sneakers.common.v1.HealthService/Check", "rpc.response.status_code", "STATUS_CODE_ERROR"} {
				if !strings.Contains(got, want) {
					t.Errorf("export lacks %q: %s", want, got)
				}
			}
		})
	}
}

func TestSpanNamesAndMetricAttributesAreFiltered(t *testing.T) {
	c := collectortest.Start(t, codes.OK)
	conn, stop := serve(t, c, &fakeHealth{do: func(ctx context.Context) error {
		_, span := otelapi.Tracer("test").Start(ctx, canary)
		span.End()
		otel.NewCounter("connector_canary_total", "A test counter.").Add(ctx, 1,
			otel.KV("rpc.method", canary), otel.KV("leak", canary))
		return nil
	}})
	if err := call(t, context.Background(), conn, checkMethod); err != nil {
		t.Fatalf("call: %v", err)
	}
	stop()

	got := c.Text()
	if strings.Contains(got, canary) {
		t.Fatalf("canary exported: %s", got)
	}
	for _, want := range []string{"[span]", "connector_canary_total", "sneakers.common.v1.HealthService/Check"} {
		if !strings.Contains(got, want) {
			t.Errorf("export lacks %q: %s", want, got)
		}
	}
}

func TestResourceCarriesOnlyTheServiceName(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "leak="+canary)
	c := collectortest.Start(t, codes.OK)
	conn, stop := serve(t, c, &fakeHealth{do: func(context.Context) error { return nil }})
	if err := call(t, context.Background(), conn, checkMethod); err != nil {
		t.Fatalf("call: %v", err)
	}
	stop()

	got := c.Text()
	if strings.Contains(got, canary) {
		t.Fatalf("canary exported: %s", got)
	}
	if !strings.Contains(got, "connector") {
		t.Errorf("export lacks the service name: %s", got)
	}
}

func TestBaggageIsNotTaken(t *testing.T) {
	c := collectortest.Start(t, codes.OK)
	var members int
	conn, stop := serve(t, c, &fakeHealth{do: func(ctx context.Context) error {
		members = baggage.FromContext(ctx).Len()
		return nil
	}})
	ctx := metadata.AppendToOutgoingContext(context.Background(), "baggage", "leak="+canary)
	if err := call(t, ctx, conn, checkMethod); err != nil {
		t.Fatalf("call: %v", err)
	}
	stop()

	if members != 0 {
		t.Fatalf("handler saw %d baggage members", members)
	}
	if strings.Contains(c.Text(), canary) {
		t.Fatalf("canary exported: %s", c.Text())
	}
}

// go-workload-identity fills outcome with err.Error().
func TestOutcomeIsNeverExported(t *testing.T) {
	if slices.Contains(telemetry.AllowedLogFields, "outcome") {
		t.Fatal("outcome is free text and must stay off the list")
	}
	c := collectortest.Start(t, codes.OK)
	s, stop := startLogs(t, c.Endpoint)
	lg := log.NewLoggerWithOptions("connector", log.WithOutput(s.Output(&bytes.Buffer{})))
	lg.Warn("jwks fetch failed", log.F("outcome", canary))
	stop()

	got := c.Text()
	if !strings.Contains(got, "jwks fetch failed") {
		t.Fatalf("line not exported: %s", got)
	}
	if strings.Contains(got, "outcome") || strings.Contains(got, canary) {
		t.Fatalf("outcome exported: %s", got)
	}
}

func TestSDKErrorsDoNotReachAnEarlierHandler(t *testing.T) {
	var called bool
	otelapi.SetErrorHandler(otelapi.ErrorHandlerFunc(func(error) { called = true }))
	c := collectortest.Start(t, codes.OK)
	_, stop := startLogs(t, c.Endpoint)
	defer stop()

	otelapi.Handle(errors.New("dial https://user:" + canary + "@collector.example:4317"))
	if called {
		t.Fatal("the SDK's error handler was not replaced")
	}
}
