// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"golang.org/x/crypto/ssh"
)

// These tests run the heartbeat against a real OpenSSH server (9.8 or later,
// so PerSourcePenalties applies) with LogLevel VERBOSE, in a throwaway
// container, and read sshd's own log to see what the target saw. They need
// docker; the container installs OpenSSH from the Alpine repository.
const opensshImage = "alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507"

const sshdConfig = `Port 22
HostKey /etc/ssh/test_host_key
LogLevel VERBOSE
PerSourcePenalties yes
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
StrictModes no
`

// The account's password, for this throwaway container only.
const opensshTestPassword = "ci-only-heartbeat-password"

const sshdEntrypoint = `set -e
apk add --no-cache -q openssh-server >/dev/null
adduser -D -h /var/lib/svc svc
echo "svc:` + opensshTestPassword + `" | chpasswd
install -m 600 /cfg/host_key /etc/ssh/test_host_key
mkdir -p /var/lib/svc/.ssh
cp /cfg/authorized_keys /var/lib/svc/.ssh/authorized_keys
chown -R svc /var/lib/svc/.ssh
/usr/sbin/sshd -V 2>&1
exec /usr/sbin/sshd -D -e -f /cfg/sshd_config
`

type opensshServer struct {
	t       *testing.T
	name    string
	port    int
	hostKey ssh.Signer
	keyPEM  string
}

func startOpenSSH(t *testing.T) *opensshServer {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is required: %v", err)
	}
	keyPEM, clientPub := clientKeyPEM(t)
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostBlock, err := ssh.MarshalPrivateKey(hostPriv, "")
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	hostKey, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	dir := t.TempDir()
	files := map[string][]byte{
		"host_key":        pem.EncodeToMemory(hostBlock),
		"authorized_keys": ssh.MarshalAuthorizedKey(clientPub),
		"sshd_config":     []byte(sshdConfig),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	name := "sneakers-connector-openssh-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	run := exec.Command("docker", "run", "-d", "--name", name, "-p", "127.0.0.1::22",
		"-v", dir+":/cfg:ro", opensshImage, "sh", "-c", sshdEntrypoint)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v: %s", err, out)
	}
	srv := &opensshServer{t: t, name: name, hostKey: hostKey, keyPEM: keyPEM}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("sshd log:\n%s", srv.log())
		}
		_ = exec.Command("docker", "rm", "-f", "-v", name).Run()
	})

	// Wait on sshd's own log, not a TCP probe: a probe would itself be a
	// connection without authentication.
	deadline := time.Now().Add(2 * time.Minute)
	for !strings.Contains(srv.log(), "Server listening on 0.0.0.0 port 22") {
		if time.Now().After(deadline) {
			t.Fatalf("sshd did not start:\n%s", srv.log())
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, err := exec.Command("docker", "port", name, "22/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	srv.port, err = strconv.Atoi(hostPort[strings.LastIndex(hostPort, ":")+1:])
	if err != nil {
		t.Fatalf("parse port %q: %v", hostPort, err)
	}
	return srv
}

func (s *opensshServer) log() string {
	out, _ := exec.Command("docker", "logs", s.name).CombinedOutput()
	return string(out)
}

// settledLog returns sshd's log once the session children have exited, which
// is when sshd logs a penalty.
func (s *opensshServer) settledLog() string {
	time.Sleep(2 * time.Second)
	return s.log()
}

func (s *opensshServer) job(pins ...string) *vaultv1.HeartbeatJob {
	return &vaultv1.HeartbeatJob{
		SecretId:   "sec-openssh",
		Connection: &vaultv1.HeartbeatConn{Protocol: "ssh", Host: "127.0.0.1", Port: int32(s.port)},
		Target:     &vaultv1.HeartbeatTarget{Kind: "linux", SshHostKeys: pins},
	}
}

func countLines(log, substr string) int {
	n := 0
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func TestOpenSSHHeartbeatOfUnpinnedTargetMakesNoConnection(t *testing.T) {
	srv := startOpenSSH(t)
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{srv.job()},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: srv.keyPEM},
	}
	runTicksN(fc, 3, nil)

	log := srv.settledLog()
	if n := countLines(log, "Connection from"); n != 0 {
		t.Fatalf("sshd saw %d connections, want none", n)
	}
	if n := countLines(log, "srclimit_penalise"); n != 0 {
		t.Fatalf("sshd penalised the connector %d times, want none", n)
	}
	for _, r := range fc.reports {
		if r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED {
			t.Fatalf("report = %v, want HOST_KEY_NOT_PINNED", r.GetResult())
		}
	}
}

func TestOpenSSHHeartbeatOfPinnedTargetAuthenticatesAndClosesCleanly(t *testing.T) {
	srv := startOpenSSH(t)
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey.PublicKey())))
	cases := []struct {
		name   string
		reveal *vaultv1.RevealForHeartbeatResponse
		want   string
	}{
		{"publickey", &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: srv.keyPEM}, "Accepted publickey for svc"},
		{"password", &vaultv1.RevealForHeartbeatResponse{Username: "svc", Password: opensshTestPassword}, "Accepted password for svc"},
	}
	for _, tc := range cases {
		fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{srv.job(pin)}, heartbeatReveal: tc.reveal}
		runTicksN(fc, 2, nil)
		for _, r := range fc.reports {
			if r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
				t.Fatalf("%s: report = %v %q, want OK", tc.name, r.GetResult(), r.GetDetail())
			}
		}
		if n := countLines(srv.settledLog(), tc.want); n != 2 {
			t.Fatalf("%s: sshd logged %q %d times, want once per heartbeat", tc.name, tc.want, n)
		}
	}

	log := srv.log()
	if n := countLines(log, "port 22 rdomain"); n != 4 {
		t.Fatalf("sshd saw %d connections, want one per heartbeat", n)
	}
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "Connection closed") && strings.Contains(line, "[preauth]") {
			t.Fatalf("sshd logged a close before authentication: %s", line)
		}
	}
	if n := countLines(log, "srclimit_penalise"); n != 0 {
		t.Fatalf("sshd penalised the connector %d times, want none", n)
	}
}

// A mismatch costs exactly one connection, refused during key exchange
// before anything is sent; every later heartbeat is reported without
// contacting the target. That one refused exchange is all sshd can see.
func TestOpenSSHHeartbeatStopsAfterOneMismatch(t *testing.T) {
	srv := startOpenSSH(t)
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	wrong, err := ssh.NewSignerFromSigner(wrongPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	fc := &fakeVaultClient{
		jobs:            []*vaultv1.HeartbeatJob{srv.job(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(wrong.PublicKey()))))},
		heartbeatReveal: &vaultv1.RevealForHeartbeatResponse{Username: "svc", PrivateKey: srv.keyPEM},
	}
	runTicksN(fc, 5, nil)

	log := srv.settledLog()
	if n := countLines(log, "Connection from"); n != 1 {
		t.Fatalf("sshd saw %d connections, want exactly one", n)
	}
	if n := countLines(log, "Accepted"); n != 0 {
		t.Fatalf("authenticated to a host with the wrong key")
	}
	if n := countLines(log, "srclimit_penalise"); n > 1 {
		t.Fatalf("sshd penalised the connector %d times, want at most once", n)
	}
	for _, r := range fc.reports {
		if r.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH {
			t.Fatalf("report = %v, want HOST_KEY_MISMATCH", r.GetResult())
		}
	}
	t.Logf("sshd penalties for the one refused key exchange: %d", countLines(log, "srclimit_penalise"))
}
