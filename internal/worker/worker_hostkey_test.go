// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	"golang.org/x/crypto/ssh"
)

var testPins = []string{
	"ssh-ed25519 AAAA-fake-pin-a host-a",
	"ssh-ed25519 AAAA-fake-pin-b host-b",
}

func TestHeartbeatPassesTheTargetsHostKeyPins(t *testing.T) {
	const protocol = "worker-test-pins"
	fa := &fakeAdapter{result: adapter.Valid}
	adapter.Register(protocol, fa)

	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-ssh",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app01.example.org", Port: 22},
		Target:     &vaultv1.HeartbeatTarget{Kind: "linux", SshHostKeys: testPins},
	}}}
	runOnce(fc)

	if !reflect.DeepEqual(fa.gotConn.HostKeys, testPins) {
		t.Fatalf("validate conn host keys = %v, want %v", fa.gotConn.HostKeys, testPins)
	}
}

func TestRotationPassesTheTargetsHostKeyPins(t *testing.T) {
	const protocol = "worker-test-rotate-pins"
	fa := &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid}
	adapter.Register(protocol, fa)

	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-ssh",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app01.example.org", Port: 22},
		Target:     &vaultv1.HeartbeatTarget{Kind: "linux", SshHostKeys: testPins},
	}}}
	runOnce(fc)

	if !reflect.DeepEqual(fa.gotRotateConn.HostKeys, testPins) {
		t.Fatalf("rotate conn host keys = %v, want %v", fa.gotRotateConn.HostKeys, testPins)
	}
}

func TestHeartbeatReportsHostKeyRefusalsAsTheirOwnResults(t *testing.T) {
	cases := []struct {
		protocol string
		result   adapter.Result
		detail   string
		want     vaultv1.HeartbeatResult
	}{
		{"worker-test-not-pinned", adapter.HostKeyNotPinned, "host key not pinned for this target (presented SHA256:abc)", vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED},
		{"worker-test-mismatch", adapter.HostKeyMismatch, "host key mismatch (presented SHA256:abc)", vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			adapter.Register(tc.protocol, &fakeAdapter{result: tc.result, detail: tc.detail})
			fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
				SecretId:   "sec-ssh",
				Connection: &vaultv1.HeartbeatConn{Protocol: tc.protocol, Host: "app01.example.org", Port: 22},
			}}}
			runOnce(fc)

			if len(fc.reports) != 1 {
				t.Fatalf("reports = %d, want 1", len(fc.reports))
			}
			if got := fc.reports[0]; got.GetResult() != tc.want || got.GetDetail() != tc.detail {
				t.Fatalf("report = %v %q, want %v %q", got.GetResult(), got.GetDetail(), tc.want, tc.detail)
			}
		})
	}
}

// The real ssh adapter, driven through the worker against a throwaway SSH
// server the job has no pins for, reports HOST_KEY_NOT_PINNED.
func TestSSHHeartbeatOfUnpinnedTargetIsReportedNotPinned(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("no keys accepted")
		},
	}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _, _, _ = ssh.NewServerConn(c, cfg) }()
		}
	}()

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	fc := &fakeVaultClient{
		jobs: []*vaultv1.HeartbeatJob{{
			SecretId:   "sec-ssh",
			Connection: &vaultv1.HeartbeatConn{Protocol: "ssh", Host: "127.0.0.1", Port: int32(ln.Addr().(*net.TCPAddr).Port)},
			Target:     &vaultv1.HeartbeatTarget{Kind: "linux"},
		}},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: string(pem.EncodeToMemory(block))},
	}
	runOnce(fc)

	if len(fc.reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(fc.reports))
	}
	got := fc.reports[0]
	if got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED {
		t.Fatalf("result = %v (%s), want HOST_KEY_NOT_PINNED", got.GetResult(), got.GetDetail())
	}
	if !strings.Contains(got.GetDetail(), ssh.FingerprintSHA256(hostSigner.PublicKey())) {
		t.Fatalf("detail = %q, want the presented fingerprint", got.GetDetail())
	}
}

func TestHostKeyResultsMapping(t *testing.T) {
	if got := toHeartbeatResult(adapter.HostKeyNotPinned); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED {
		t.Errorf("toHeartbeatResult(HostKeyNotPinned) = %v", got)
	}
	if got := toHeartbeatResult(adapter.HostKeyMismatch); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH {
		t.Errorf("toHeartbeatResult(HostKeyMismatch) = %v", got)
	}
	for _, r := range []adapter.Result{adapter.HostKeyNotPinned, adapter.HostKeyMismatch} {
		if got := toRotationPhase(r); got != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
			t.Errorf("toRotationPhase(%v) = %v, want FAILED", r, got)
		}
	}
}
