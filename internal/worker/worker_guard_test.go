// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

// tickingVault hands out the fake's jobs on each of the first stopAfter
// claims, calls beforeTick(n) ahead of claim n, and cancels the run on the
// last one, so a test drives an exact number of ticks through Run.
type tickingVault struct {
	*fakeVaultClient
	ticks      int
	stopAfter  int
	cancel     context.CancelFunc
	beforeTick func(n int)
}

func (v *tickingVault) ClaimDueHeartbeats(ctx context.Context, in *vaultv1.ClaimDueHeartbeatsRequest, opts ...grpc.CallOption) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	v.ticks++
	if v.ticks > v.stopAfter {
		return &vaultv1.ClaimDueHeartbeatsResponse{}, nil
	}
	if v.beforeTick != nil {
		v.beforeTick(v.ticks)
	}
	if v.ticks == v.stopAfter {
		v.cancel()
	}
	return v.fakeVaultClient.ClaimDueHeartbeats(ctx, in, opts...)
}

// runTicksN runs the worker for n ticks against fc, all in one Run, so the
// worker keeps what it learned about a target from one tick to the next.
func runTicksN(fc *fakeVaultClient, n int, beforeTick func(int)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Run(ctx, &tickingVault{fakeVaultClient: fc, stopAfter: n, cancel: cancel, beforeTick: beforeTick}, "dev-connector-token", time.Millisecond)
}

// setClock fixes the worker's clock at *at for the test.
func setClock(t *testing.T, at *time.Time) {
	t.Helper()
	prev := now
	now = func() time.Time { return *at }
	t.Cleanup(func() { now = prev })
}

// countingAdapter returns a fixed outcome and counts its Validate calls.
type countingAdapter struct {
	result adapter.Result
	detail string
	calls  atomic.Int32
}

func (a *countingAdapter) Validate(context.Context, adapter.Conn, adapter.Cred) (adapter.Result, string) {
	a.calls.Add(1)
	return a.result, a.detail
}

func (a *countingAdapter) Rotate(context.Context, adapter.Conn, adapter.Cred, string) (adapter.Result, string) {
	return adapter.Unreachable, "not used"
}

// sshTestServer is an in-process SSH server that counts the TCP connections
// it accepts and the authentications it allows.
type sshTestServer struct {
	host     string
	port     int
	hostKey  ssh.Signer
	accepted atomic.Int32
	authOK   atomic.Int32
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func pinFor(s ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// clientKeyPEM returns an OpenSSH private key and its public key, generated
// per run.
func clientKeyPEM(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("client pub: %v", err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

// startSSHTestServer accepts authorizedPub, or password for user svc.
func startSSHTestServer(t *testing.T, authorizedPub ssh.PublicKey, password string) *sshTestServer {
	t.Helper()
	srv := &sshTestServer{hostKey: newSigner(t)}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedPub != nil && string(key.Marshal()) == string(authorizedPub.Marshal()) {
				srv.authOK.Add(1)
				return &ssh.Permissions{}, nil
			}
			return nil, errNotAuthorized
		},
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if password != "" && m.User() == "svc" && string(pw) == password {
				srv.authOK.Add(1)
				return &ssh.Permissions{}, nil
			}
			return nil, errNotAuthorized
		},
	}
	cfg.AddHostKey(srv.hostKey)
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
			srv.accepted.Add(1)
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no sessions in test")
				}
				_ = sc.Close()
			}()
		}
	}()
	srv.host, srv.port = "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
	return srv
}

type notAuthorizedError struct{}

func (notAuthorizedError) Error() string { return "not authorized" }

var errNotAuthorized = notAuthorizedError{}

func sshJob(srv *sshTestServer, pins ...string) *vaultv1.HeartbeatJob {
	return &vaultv1.HeartbeatJob{
		SecretId:   "sec-ssh",
		Connection: &vaultv1.HeartbeatConn{Protocol: "ssh", Host: srv.host, Port: int32(srv.port)},
		Target:     &vaultv1.HeartbeatTarget{Kind: "linux", SshHostKeys: pins},
	}
}

func TestSSHHeartbeatOfUnpinnedTargetNeverConnects(t *testing.T) {
	keyPEM, pub := clientKeyPEM(t)
	srv := startSSHTestServer(t, pub, "")
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{sshJob(srv)},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: keyPEM},
	}
	runTicksN(fc, 3, nil)

	if n := srv.accepted.Load(); n != 0 {
		t.Fatalf("target accepted %d connections, want none", n)
	}
	if len(fc.revealed) != 0 {
		t.Fatalf("revealed %v for an unpinned target, want no reveal", fc.revealed)
	}
	if len(fc.reports) != 3 {
		t.Fatalf("reports = %d, want one per tick", len(fc.reports))
	}
	for _, r := range fc.reports {
		if r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED || !strings.Contains(r.GetDetail(), "pin the host key first") {
			t.Fatalf("report = %v %q, want HOST_KEY_NOT_PINNED telling the admin to pin the host key first", r.GetResult(), r.GetDetail())
		}
	}
}

func TestSSHHeartbeatOfPinnedTargetSignsInWithTheKey(t *testing.T) {
	keyPEM, pub := clientKeyPEM(t)
	srv := startSSHTestServer(t, pub, "")
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{sshJob(srv, pinFor(srv.hostKey))},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: keyPEM},
	}
	runTicksN(fc, 1, nil)

	if len(fc.reports) != 1 || fc.reports[0].GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
		t.Fatalf("reports = %v, want one OK", fc.reports)
	}
	if n := srv.authOK.Load(); n != 1 {
		t.Fatalf("authentications = %d, want 1", n)
	}
}

func TestSSHHeartbeatOfPinnedTargetSignsInWithThePassword(t *testing.T) {
	srv := startSSHTestServer(t, nil, "correct horse")
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{sshJob(srv, pinFor(srv.hostKey))},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", Password: "correct horse"},
	}
	runTicksN(fc, 1, nil)

	if len(fc.reports) != 1 || fc.reports[0].GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
		t.Fatalf("reports = %v, want one OK", fc.reports)
	}
	if n := srv.authOK.Load(); n != 1 {
		t.Fatalf("authentications = %d, want 1", n)
	}
}

func TestSSHHeartbeatStopsAfterAHostKeyMismatch(t *testing.T) {
	keyPEM, pub := clientKeyPEM(t)
	srv := startSSHTestServer(t, pub, "")
	wrong := newSigner(t)
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{sshJob(srv, pinFor(wrong))},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: keyPEM},
	}
	runTicksN(fc, 4, nil)

	if n := srv.accepted.Load(); n != 1 {
		t.Fatalf("target accepted %d connections, want exactly one", n)
	}
	if n := srv.authOK.Load(); n != 0 {
		t.Fatalf("authenticated %d times to a host with the wrong key", n)
	}
	if len(fc.reports) != 4 {
		t.Fatalf("reports = %d, want one per tick", len(fc.reports))
	}
	presented := ssh.FingerprintSHA256(srv.hostKey.PublicKey())
	pinned := ssh.FingerprintSHA256(wrong.PublicKey())
	for i, r := range fc.reports {
		if r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH {
			t.Fatalf("report %d = %v, want HOST_KEY_MISMATCH", i, r.GetResult())
		}
		if !strings.Contains(r.GetDetail(), presented) || !strings.Contains(r.GetDetail(), pinned) {
			t.Fatalf("report %d detail = %q, want presented %s and pinned %s", i, r.GetDetail(), presented, pinned)
		}
		if i > 0 && !strings.Contains(r.GetDetail(), "heartbeat stopped") {
			t.Fatalf("report %d detail = %q, want it to say the heartbeat stopped", i, r.GetDetail())
		}
	}

	// Re-pinning the target to the key it presents lets the heartbeat run again.
	fc.jobs = []*vaultv1.HeartbeatJob{sshJob(srv, pinFor(srv.hostKey))}
	fc.reports = nil
	runTicksN(fc, 1, nil)
	if len(fc.reports) != 1 || fc.reports[0].GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
		t.Fatalf("after re-pinning, reports = %v, want one OK", fc.reports)
	}
}

func TestUnreachableTargetIsBackedOffExponentiallyAndCapped(t *testing.T) {
	const protocol = "worker-test-backoff"
	ca := &countingAdapter{}
	adapter.Register(protocol, ca)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	setClock(t, &clock)
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-down",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "app02.example.org", Port: 22},
	}}}

	// Each step: how far the clock moves before the tick, what the target
	// answers if it is contacted, and whether it should be.
	steps := []struct {
		advance time.Duration
		result  adapter.Result
		contact bool
	}{
		{0, adapter.Unreachable, true},                          // first failure: back off 1x
		{backoffBase - time.Second, adapter.Unreachable, false}, // inside 1x
		{time.Second, adapter.Unreachable, true},                // second failure: 2x
		{2*backoffBase - time.Second, adapter.Unreachable, false},
		{time.Second, adapter.Unreachable, true},     // third: 4x
		{4 * backoffBase, adapter.Unreachable, true}, // fourth: 8x
		{8 * backoffBase, adapter.Unreachable, true}, // fifth: 16x, over the cap
		{backoffMax - time.Second, adapter.Unreachable, false},
		{time.Second, adapter.Valid, true},       // recovered: backoff cleared
		{0, adapter.Unreachable, true},           // fails again: 1x
		{backoffBase, adapter.Unreachable, true}, // retried after one base interval
	}
	var want int32
	check := func(i int) {
		st := steps[i]
		if st.contact {
			want++
		}
		if got := ca.calls.Load(); got != want {
			t.Fatalf("step %d: target contacted %d times in all, want %d", i, got, want)
		}
		r := fc.reports[i]
		if !st.contact && (r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE || !strings.Contains(r.GetDetail(), "backing off")) {
			t.Fatalf("step %d: report = %v %q, want UNREACHABLE saying the heartbeat is backing off", i, r.GetResult(), r.GetDetail())
		}
	}
	runTicksN(fc, len(steps), func(n int) {
		if n > 1 {
			check(n - 2)
		}
		st := steps[n-1]
		clock = clock.Add(st.advance)
		ca.result = st.result
	})
	check(len(steps) - 1)
	if len(fc.reports) != len(steps) {
		t.Fatalf("reports = %d, want one per tick", len(fc.reports))
	}
}
