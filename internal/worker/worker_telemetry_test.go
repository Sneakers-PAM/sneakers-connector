// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"bytes"
	"context"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry/collectortest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const targetCanary = "CANARY-target-5e1d"

// claimFails makes the vault's claim fail with err.
type claimFails struct {
	fakeVaultClient
	err error
}

func (c *claimFails) ClaimDueHeartbeats(context.Context, *vaultv1.ClaimDueHeartbeatsRequest, ...grpc.CallOption) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	return nil, c.err
}

func exportedLogger(t *testing.T) (log.Logger, *collectortest.Collector, func()) {
	t.Helper()
	t.Setenv("LOG_FORMAT", "json")
	c := collectortest.Start(t, codes.OK)
	s := telemetry.Settings{Endpoint: c.Endpoint, Logs: true}
	shutdown, err := otel.InitWithOptions(context.Background(), "connector", c.Endpoint, s.Options()...)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	lg := log.NewLoggerWithOptions("connector", log.WithOutput(s.Output(&bytes.Buffer{})))
	return lg, c, func() { _ = shutdown(context.Background()) }
}

func TestTargetErrorTextStaysOutOfExportedLogs(t *testing.T) {
	const protocol = "worker-test-canary"
	adapter.Register(protocol, &fakeAdapter{result: adapter.UntrustedCertificate, detail: "server said " + targetCanary})
	job := &vaultv1.HeartbeatJob{SecretId: "sec-canary", Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.example.org", Port: 636}}
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{job}}

	lg, c, stop := exportedLogger(t)
	tick(context.Background(), lg, fc, &vaultv1.WorkerIdentity{}, newTargetGuard())
	stop()

	got := c.Text()
	if strings.Contains(got, targetCanary) {
		t.Fatalf("target text exported: %s", got)
	}
	for _, want := range []string{"sec-canary", adapter.UntrustedCertificate.String()} {
		if !strings.Contains(got, want) {
			t.Errorf("export lacks %q: %s", want, got)
		}
	}
}

func TestVaultErrorExportsItsCodeNotItsText(t *testing.T) {
	fc := &claimFails{err: status.Error(codes.Unauthenticated, targetCanary)}

	lg, c, stop := exportedLogger(t)
	tick(context.Background(), lg, fc, &vaultv1.WorkerIdentity{}, newTargetGuard())
	stop()

	got := c.Text()
	if strings.Contains(got, targetCanary) {
		t.Fatalf("error text exported: %s", got)
	}
	if !strings.Contains(got, codes.Unauthenticated.String()) {
		t.Errorf("export lacks the code: %s", got)
	}
}
