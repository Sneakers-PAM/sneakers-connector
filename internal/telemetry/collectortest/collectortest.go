// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package collectortest runs an in-process OTLP log collector for tests.
package collectortest

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	logspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// Collector records every log export it receives as JSON.
type Collector struct {
	logspb.UnimplementedLogsServiceServer

	// Endpoint is the plaintext URL to export to.
	Endpoint string

	mu     sync.Mutex
	got    []string
	reject codes.Code
}

// Start serves a collector until the test ends. A nonzero reject fails every
// export with that code.
func Start(t *testing.T, reject codes.Code) *Collector {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &Collector{Endpoint: "http://" + lis.Addr().String(), reject: reject}
	s := grpc.NewServer()
	logspb.RegisterLogsServiceServer(s, c)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return c
}

// Export implements the OTLP logs service.
func (c *Collector) Export(_ context.Context, req *logspb.ExportLogsServiceRequest) (*logspb.ExportLogsServiceResponse, error) {
	if c.reject != codes.OK {
		return nil, status.Error(c.reject, "rejected")
	}
	b, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, string(b))
	return &logspb.ExportLogsServiceResponse{}, nil
}

// Text returns everything received so far.
func (c *Collector) Text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.got, "\n")
}
