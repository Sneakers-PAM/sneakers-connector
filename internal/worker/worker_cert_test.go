// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// An untrusted certificate is a trust problem, not a reachability one: the
// worker reports its detail as it is and keeps checking the target on
// schedule, never backing off as if the target were down.
func TestUntrustedCertificateIsNotBackedOff(t *testing.T) {
	const protocol = "worker-test-untrusted-cert"
	const detail = "dial ldaps://dc01.ad.example.org:636: untrusted certificate: the certificate for dc01.ad.example.org is signed by Example Intermediate CA G1, which isn't in the trusted CA list"
	ca := &countingAdapter{result: adapter.UntrustedCertificate, detail: detail}
	adapter.Register(protocol, ca)
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-untrusted",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.ad.example.org", Port: 636, UseTls: true},
	}}}

	runTicksN(fc, 3, nil)

	if got := ca.calls.Load(); got != 3 {
		t.Fatalf("target contacted %d times over 3 ticks, want 3 (no backoff for an untrusted certificate)", got)
	}
	for i, r := range fc.reports {
		if r.GetDetail() != detail {
			t.Fatalf("report %d detail = %q, want %q", i, r.GetDetail(), detail)
		}
	}
}

func TestUntrustedCertificateMapping(t *testing.T) {
	if got := toHeartbeatResult(adapter.UntrustedCertificate); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNTRUSTED_CERTIFICATE {
		t.Errorf("toHeartbeatResult(UntrustedCertificate) = %v, want UNTRUSTED_CERTIFICATE", got)
	}
	if got := toRotationPhase(adapter.UntrustedCertificate); got != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Errorf("toRotationPhase(UntrustedCertificate) = %v, want FAILED", got)
	}
}
