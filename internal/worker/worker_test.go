// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// fakeVaultClient is a hand-rolled vaultv1.VaultServiceClient: it embeds the
// (nil) interface to satisfy every method the worker doesn't exercise, and
// overrides only the RPCs the worker calls (heartbeat + rotation),
// recording what it was asked to do so tests can assert on the sequence.
// Zero-value rotationJobs means ClaimDueRotations reports nothing due, so
// heartbeat-only tests (which never set it) never drive any rotation
// processing -- Run always calls rotationTick too, so this must be safe by
// default rather than nil-panicking on the embedded interface.
type fakeVaultClient struct {
	vaultv1.VaultServiceClient

	jobs []*vaultv1.HeartbeatJob

	claimedLimit int32
	claimedToken string
	revealed     []string
	reports      []*vaultv1.ReportHeartbeatRequest

	rotationJobs []*vaultv1.RotationJob

	rotationClaimedLimit int32
	revealedRotations    []string
	rotationReports      []*vaultv1.ReportRotationRequest
}

func (f *fakeVaultClient) ClaimDueHeartbeats(_ context.Context, in *vaultv1.ClaimDueHeartbeatsRequest, _ ...grpc.CallOption) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	f.claimedLimit = in.GetLimit()
	f.claimedToken = in.GetIdentity().GetToken()
	return &vaultv1.ClaimDueHeartbeatsResponse{Jobs: f.jobs}, nil
}

func (f *fakeVaultClient) RevealForHeartbeat(_ context.Context, in *vaultv1.RevealForHeartbeatRequest, _ ...grpc.CallOption) (*vaultv1.RevealForHeartbeatResponse, error) {
	f.revealed = append(f.revealed, in.GetSecretId())
	return &vaultv1.RevealForHeartbeatResponse{Username: "svc-example", Password: "hunter2"}, nil
}

func (f *fakeVaultClient) ReportHeartbeat(_ context.Context, in *vaultv1.ReportHeartbeatRequest, _ ...grpc.CallOption) (*vaultv1.ReportHeartbeatResponse, error) {
	f.reports = append(f.reports, in)
	return &vaultv1.ReportHeartbeatResponse{Ok: true}, nil
}

func (f *fakeVaultClient) ClaimDueRotations(_ context.Context, in *vaultv1.ClaimDueRotationsRequest, _ ...grpc.CallOption) (*vaultv1.ClaimDueRotationsResponse, error) {
	f.rotationClaimedLimit = in.GetLimit()
	return &vaultv1.ClaimDueRotationsResponse{Jobs: f.rotationJobs}, nil
}

func (f *fakeVaultClient) RevealForRotation(_ context.Context, in *vaultv1.RevealForRotationRequest, _ ...grpc.CallOption) (*vaultv1.RevealForRotationResponse, error) {
	f.revealedRotations = append(f.revealedRotations, in.GetSecretId())
	return &vaultv1.RevealForRotationResponse{Username: "svc-example", CurrentPassword: "hunter2", NewPassword: "hunter3", Version: 7}, nil
}

func (f *fakeVaultClient) ReportRotation(_ context.Context, in *vaultv1.ReportRotationRequest, _ ...grpc.CallOption) (*vaultv1.ReportRotationResponse, error) {
	f.rotationReports = append(f.rotationReports, in)
	return &vaultv1.ReportRotationResponse{Ok: true}, nil
}

// fakeAdapter records the Conn/Cred it was asked to validate/rotate and
// returns fixed Results/details, so tests can drive both the Valid and
// Unreachable paths through the worker for both heartbeat and rotation.
type fakeAdapter struct {
	result adapter.Result
	detail string

	rotateResult adapter.Result
	rotateDetail string

	gotConn adapter.Conn
	gotCred adapter.Cred
	called  bool

	gotRotateConn    adapter.Conn
	gotRotateCurrent adapter.Cred
	gotNewPassword   string
	rotateCalled     bool
}

func (a *fakeAdapter) Validate(_ context.Context, c adapter.Conn, cred adapter.Cred) (adapter.Result, string) {
	a.called = true
	a.gotConn = c
	a.gotCred = cred
	return a.result, a.detail
}

func (a *fakeAdapter) Rotate(_ context.Context, c adapter.Conn, current adapter.Cred, newPassword string) (adapter.Result, string) {
	a.rotateCalled = true
	a.gotRotateConn = c
	a.gotRotateCurrent = current
	a.gotNewPassword = newPassword
	return a.rotateResult, a.rotateDetail
}

// runOnce drives worker.Run for exactly one immediate tick: Run always
// processes one batch before entering its ticker loop, so a
// pre-cancelled context makes the single tick deterministic (no reliance on
// timing) while still exercising the real Run entrypoint.
func runOnce(vc vaultv1.VaultServiceClient) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Run(ctx, vc, "dev-connector-token", time.Hour)
}

func TestRunClaimsRevealsValidatesReportsInSequence(t *testing.T) {
	const protocol = "worker-test-valid"
	fa := &fakeAdapter{result: adapter.Valid}
	adapter.Register(protocol, fa)

	job := &vaultv1.HeartbeatJob{
		SecretId: "sec-1",
		Username: "svc-example",
		Connection: &vaultv1.HeartbeatConn{
			Protocol: protocol,
			Host:     "dc1.ad.example.org",
			Port:     636,
			UseTls:   true,
		},
		Target: &vaultv1.HeartbeatTarget{
			Kind:   "ad",
			Domain: "ad.example.org",
		},
	}
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{job}}

	runOnce(fc)

	if fc.claimedToken != "dev-connector-token" {
		t.Fatalf("claim token = %q, want dev-connector-token", fc.claimedToken)
	}
	if fc.claimedLimit != claimLimit {
		t.Fatalf("claim limit = %d, want %d", fc.claimedLimit, claimLimit)
	}
	if len(fc.revealed) != 1 || fc.revealed[0] != "sec-1" {
		t.Fatalf("revealed = %v, want [sec-1]", fc.revealed)
	}
	if !fa.called {
		t.Fatal("adapter.Validate was never called")
	}
	if fa.gotCred.Username != "svc-example" || fa.gotCred.Password != "hunter2" {
		t.Fatalf("validate cred = %+v, want revealed username/password", fa.gotCred)
	}
	wantConn := adapter.Conn{Host: "dc1.ad.example.org", Port: 636, UseTLS: true, Domain: "ad.example.org"}
	if fa.gotConn != wantConn {
		t.Fatalf("validate conn = %+v, want %+v", fa.gotConn, wantConn)
	}
	if len(fc.reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(fc.reports))
	}
	got := fc.reports[0]
	if got.GetSecretId() != "sec-1" || got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
		t.Fatalf("report = %+v, want secret sec-1 result OK", got)
	}
}

func TestRunReportsUnreachableWithoutCrashing(t *testing.T) {
	const protocol = "worker-test-unreachable"
	fa := &fakeAdapter{result: adapter.Unreachable, detail: "dial tcp: no route to host"}
	adapter.Register(protocol, fa)

	job := &vaultv1.HeartbeatJob{
		SecretId:   "sec-2",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "unreachable.ad.example.org", Port: 636},
	}
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{job}}

	runOnce(fc) // must not panic

	if len(fc.reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(fc.reports))
	}
	got := fc.reports[0]
	if got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE {
		t.Fatalf("result = %v, want UNREACHABLE", got.GetResult())
	}
	if got.GetDetail() != "dial tcp: no route to host" {
		t.Fatalf("detail = %q", got.GetDetail())
	}
}

func TestRunReportsUnreachableForJobWithNoRegisteredAdapter(t *testing.T) {
	job := &vaultv1.HeartbeatJob{
		SecretId:   "sec-3",
		Connection: &vaultv1.HeartbeatConn{Protocol: "worker-test-unregistered-protocol"},
	}
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{job}}

	runOnce(fc) // must not panic

	if len(fc.revealed) != 0 {
		t.Fatalf("revealed = %v, want none (adapter missing, no reveal attempted)", fc.revealed)
	}
	// Regression guard for I5b: a job whose protocol has no registered
	// adapter must still be reported (UNREACHABLE), not silently skipped.
	// The vault only advances a secret's next_heartbeat_at on report, so a
	// skip-without-report would leave the job due forever, re-claimed and
	// re-skipped on every tick.
	if len(fc.reports) != 1 {
		t.Fatalf("reports = %d, want 1 (unhandled job must still be reported, not skipped)", len(fc.reports))
	}
	got := fc.reports[0]
	if got.GetSecretId() != "sec-3" {
		t.Fatalf("report secret id = %q, want sec-3", got.GetSecretId())
	}
	if got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE {
		t.Fatalf("result = %v, want UNREACHABLE", got.GetResult())
	}
	if got.GetDetail() == "" {
		t.Fatal("detail = \"\", want a message naming the unregistered protocol")
	}
}

func TestRunReportsUnreachableForJobWithNilConnection(t *testing.T) {
	job := &vaultv1.HeartbeatJob{
		SecretId:   "sec-4",
		Connection: nil,
	}
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{job}}

	runOnce(fc) // must not panic

	if len(fc.revealed) != 0 {
		t.Fatalf("revealed = %v, want none (nil connection, no reveal attempted)", fc.revealed)
	}
	if len(fc.reports) != 1 {
		t.Fatalf("reports = %d, want 1 (unhandled job must still be reported, not skipped)", len(fc.reports))
	}
	if got := fc.reports[0].GetResult(); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE {
		t.Fatalf("result = %v, want UNREACHABLE", got)
	}
}

func TestToHeartbeatResultMapping(t *testing.T) {
	cases := []struct {
		in   adapter.Result
		want vaultv1.HeartbeatResult
	}{
		{adapter.Valid, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK},
		{adapter.Invalid, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED},
		{adapter.Unreachable, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE},
	}
	for _, c := range cases {
		if got := toHeartbeatResult(c.in); got != c.want {
			t.Errorf("toHeartbeatResult(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
