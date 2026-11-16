// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"reflect"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// Fingerprints are SHA-256 of invented certificates (#75).
var testTLSPins = []string{
	strings.Repeat("ab", 32),
	strings.Repeat("cd", 32),
}

func TestHeartbeatPassesTheTargetsTLSCertPins(t *testing.T) {
	const protocol = "worker-test-tls-pins"
	fa := &fakeAdapter{result: adapter.Valid}
	adapter.Register(protocol, fa)

	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-ldaps",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.ad.example.org", Port: 636, UseTls: true},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org", TlsCertPins: testTLSPins},
	}}}
	runOnce(fc)

	if !reflect.DeepEqual(fa.gotConn.TLSPins, testTLSPins) {
		t.Fatalf("validate conn tls pins = %v, want %v", fa.gotConn.TLSPins, testTLSPins)
	}
}

func TestRotationPassesTheTargetsTLSCertPins(t *testing.T) {
	const protocol = "worker-test-tls-rotate-pins"
	fa := &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid}
	adapter.Register(protocol, fa)

	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-ldaps",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.ad.example.org", Port: 636, UseTls: true},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org", TlsCertPins: testTLSPins},
	}}}
	runOnce(fc)

	if !reflect.DeepEqual(fa.gotRotateConn.TLSPins, testTLSPins) {
		t.Fatalf("rotate conn tls pins = %v, want %v", fa.gotRotateConn.TLSPins, testTLSPins)
	}
}

// A backoff or stop earned under one pin set must not follow the target once a
// person pins a different certificate.
func TestGuardKeyChangesWithTheTLSPins(t *testing.T) {
	base := adapter.Conn{Host: "dc01.ad.example.org", Port: 636}
	pinned := base
	pinned.TLSPins = testTLSPins
	if guardKey("ldap", base) == guardKey("ldap", pinned) {
		t.Fatal("guard key ignores the tls pins")
	}
	reordered := base
	reordered.TLSPins = []string{testTLSPins[1], testTLSPins[0]}
	if guardKey("ldap", pinned) != guardKey("ldap", reordered) {
		t.Fatal("guard key depends on the order of the tls pins")
	}
}

func TestHeartbeatReportsACertificateMismatchAsItsOwnResult(t *testing.T) {
	if got := toHeartbeatResult(adapter.CertificateMismatch); got != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_CERTIFICATE_MISMATCH {
		t.Fatalf("toHeartbeatResult(CertificateMismatch) = %v, want CERTIFICATE_MISMATCH", got)
	}
}
