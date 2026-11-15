// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vaultclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// claimVault answers ClaimDueHeartbeats with an empty batch and every other
// method with Unimplemented.
type claimVault struct {
	vaultv1.UnimplementedVaultServiceServer
}

func (claimVault) ClaimDueHeartbeats(context.Context, *vaultv1.ClaimDueHeartbeatsRequest) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	return &vaultv1.ClaimDueHeartbeatsResponse{}, nil
}

func startClaimVault(t *testing.T) string {
	t.Helper()
	gs := grpc.NewServer()
	vaultv1.RegisterVaultServiceServer(gs, claimVault{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	return ln.Addr().String()
}

type logLine map[string]any

func parseLines(t *testing.T, buf *bytes.Buffer) []logLine {
	t.Helper()
	var out []logLine
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var l logLine
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", raw, err)
		}
		out = append(out, l)
	}
	return out
}

func debugLogger(buf *bytes.Buffer) log.Logger {
	return log.NewLoggerWithOptions("connector", log.WithOutput(buf), log.WithDefaultLevel(log.LevelDebug), log.WithDefaultFormat(log.FormatJSON))
}

func TestDialLogsEveryOutboundCallWithTargetMethodDurationAndStatus(t *testing.T) {
	addr := startClaimVault(t)
	var buf bytes.Buffer
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}), debugLogger(&buf))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	_, _ = c.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{})

	lines := parseLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2: %s", len(lines), buf.String())
	}
	ok, failed := lines[0], lines[1]

	if ok["level"] != "debug" {
		t.Errorf("successful call level = %v, want debug", ok["level"])
	}
	if ok["method"] != vaultv1.VaultService_ClaimDueHeartbeats_FullMethodName {
		t.Errorf("method = %v", ok["method"])
	}
	if ok["target"] != addr {
		t.Errorf("target = %v, want %s", ok["target"], addr)
	}
	if ok["code"] != "OK" {
		t.Errorf("code = %v, want OK", ok["code"])
	}
	if _, has := ok["duration_ms"]; !has {
		t.Errorf("no duration_ms field: %v", ok)
	}

	if failed["level"] != "warn" {
		t.Errorf("failed call level = %v, want warn", failed["level"])
	}
	if failed["code"] != "Unimplemented" {
		t.Errorf("failed code = %v, want Unimplemented", failed["code"])
	}
	if failed["method"] != vaultv1.VaultService_ClaimDueRotations_FullMethodName {
		t.Errorf("failed method = %v", failed["method"])
	}
}

func TestDialNeverLogsARequestOrTheToken(t *testing.T) {
	addr := startClaimVault(t)
	var buf bytes.Buffer
	c, err := dial(envOf(map[string]string{"VAULT_ADDR": addr}), debugLogger(&buf))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.RevealForHeartbeat(ctx, &vaultv1.RevealForHeartbeatRequest{SecretId: "sec-canary-9f3"})

	if strings.Contains(buf.String(), "sec-canary-9f3") {
		t.Fatalf("a request field reached the log: %s", buf.String())
	}
}
