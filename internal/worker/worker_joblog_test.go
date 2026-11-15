// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// runOnceLogged is runOnce with the worker's logs captured at debug.
func runOnceLogged(vc vaultv1.VaultServiceClient) []map[string]any {
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("connector", log.WithOutput(&buf), log.WithDefaultLevel(log.LevelDebug), log.WithDefaultFormat(log.FormatJSON))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunWithLogger(ctx, vc, staticToken("dev-connector-token"), time.Hour, lg)

	var out []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var l map[string]any
		if json.Unmarshal([]byte(raw), &l) == nil {
			out = append(out, l)
		}
	}
	return out
}

func findLine(lines []map[string]any, msg string) map[string]any {
	for _, l := range lines {
		if l["message"] == msg {
			return l
		}
	}
	return nil
}

func TestHeartbeatJobLogsSecretProtocolResultAndDuration(t *testing.T) {
	const protocol = "worker-test-joblog"
	adapter.Register(protocol, &fakeAdapter{result: adapter.Valid})
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-joblog",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app01.example.org", Port: 22},
	}}}

	l := findLine(runOnceLogged(fc), "heartbeat job done")
	if l == nil {
		t.Fatal("no \"heartbeat job done\" line")
	}
	if l["secret_id"] != "sec-joblog" || l["protocol"] != protocol || l["result"] != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK.String() {
		t.Errorf("fields = %v", l)
	}
	if _, ok := l["duration_ms"]; !ok {
		t.Errorf("no duration_ms: %v", l)
	}
}

func TestRotationJobLogsSecretProtocolPhasesAndDuration(t *testing.T) {
	const protocol = "worker-test-joblog-rotate"
	adapter.Register(protocol, &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid})
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-joblog-r",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app01.example.org", Port: 22},
	}}}

	l := findLine(runOnceLogged(fc), "rotation job done")
	if l == nil {
		t.Fatal("no \"rotation job done\" line")
	}
	if l["secret_id"] != "sec-joblog-r" || l["protocol"] != protocol ||
		l["change"] != vaultv1.RotationPhase_ROTATION_PHASE_OK.String() || l["validate"] != vaultv1.RotationPhase_ROTATION_PHASE_OK.String() {
		t.Errorf("fields = %v", l)
	}
	if _, ok := l["duration_ms"]; !ok {
		t.Errorf("no duration_ms: %v", l)
	}
}

func TestJobLogsNeverCarryCredentialMaterial(t *testing.T) {
	const protocol = "worker-test-joblog-secret"
	adapter.Register(protocol, &fakeAdapter{result: adapter.Valid})
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-canary",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app01.example.org", Port: 22},
	}}, heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Password: "pw-canary-7c1"}}
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("connector", log.WithOutput(&buf), log.WithDefaultLevel(log.LevelTrace), log.WithDefaultFormat(log.FormatJSON))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RunWithLogger(ctx, fc, staticToken("tok-canary-5d2"), time.Hour, lg)
	for _, secret := range []string{"pw-canary-7c1", "tok-canary-5d2"} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("%q reached the log", secret)
		}
	}
}
