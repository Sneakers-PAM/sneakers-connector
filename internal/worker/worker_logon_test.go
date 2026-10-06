// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// The job's AD logon format reaches the adapter on heartbeat and rotation.

var testLogon = &vaultv1.LogonFormat{Format: "UPN", Netbios: "EXAMPLE", UpnSuffix: "example.org"}

func wantLogon() adapter.LogonFormat {
	return adapter.LogonFormat{Format: "UPN", Netbios: "EXAMPLE", UPNSuffix: "example.org"}
}

func TestHeartbeatPassesTheLogonFormat(t *testing.T) {
	const protocol = "worker-test-logon"
	fa := &fakeAdapter{result: adapter.Valid}
	adapter.Register(protocol, fa)
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-ad",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.example.org", Port: 636},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org"},
		Logon:      testLogon,
	}}}
	runOnce(fc)
	if fa.gotConn.Logon != wantLogon() {
		t.Fatalf("validate conn logon = %+v, want %+v", fa.gotConn.Logon, wantLogon())
	}
}

func TestRotationPassesTheLogonFormat(t *testing.T) {
	const protocol = "worker-test-rotate-logon"
	fa := &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid}
	adapter.Register(protocol, fa)
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-ad",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.example.org", Port: 636},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org"},
		Logon:      testLogon,
	}}}
	runOnce(fc)
	if fa.gotRotateConn.Logon != wantLogon() {
		t.Fatalf("rotate conn logon = %+v, want %+v", fa.gotRotateConn.Logon, wantLogon())
	}
}

func TestJobWithoutALogonFormatLeavesItUnset(t *testing.T) {
	const protocol = "worker-test-no-logon"
	fa := &fakeAdapter{result: adapter.Valid}
	adapter.Register(protocol, fa)
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{{
		SecretId:   "sec-ad",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc01.example.org", Port: 636},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org"},
	}}}
	runOnce(fc)
	if fa.gotConn.Logon != (adapter.LogonFormat{}) {
		t.Fatalf("validate conn logon = %+v, want unset", fa.gotConn.Logon)
	}
}
