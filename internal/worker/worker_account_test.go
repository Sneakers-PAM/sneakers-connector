// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"testing"

	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// flagAdapter is a fakeAdapter that also reports AccountFlags on validate.
type flagAdapter struct {
	fakeAdapter
	flags adapter.AccountFlags
}

func (a *flagAdapter) ValidateAccount(ctx context.Context, c adapter.Conn, cred adapter.Cred) (adapter.Result, string, adapter.AccountFlags) {
	r, d := a.Validate(ctx, c, cred)
	return r, d, a.flags
}

func heartbeatJob(protocol string) *vaultv1.HeartbeatJob {
	return &vaultv1.HeartbeatJob{
		SecretId:   "sec-hb",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.ad.example.org", Port: 636, UseTls: true},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org"},
	}
}

func TestHeartbeatReportsAccountFlags(t *testing.T) {
	cases := []struct {
		protocol    string
		flags       adapter.AccountFlags
		wantBuiltin bool
		wantAdmin   bool
	}{
		{"worker-flags-builtin", adapter.AccountFlags{Known: true, BuiltinAdministrator: true, AdminCount: true}, true, true},
		{"worker-flags-admincount", adapter.AccountFlags{Known: true, AdminCount: true}, false, true},
		{"worker-flags-normal", adapter.AccountFlags{Known: true}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			adapter.Register(tc.protocol, &flagAdapter{fakeAdapter: fakeAdapter{result: adapter.Valid}, flags: tc.flags})
			fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{heartbeatJob(tc.protocol)}}

			runOnce(fc)

			if len(fc.reports) != 1 {
				t.Fatalf("reports = %d, want 1", len(fc.reports))
			}
			got := fc.reports[0]
			if got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK {
				t.Fatalf("result = %v, want OK", got.GetResult())
			}
			if got.BuiltinAdministrator == nil || got.AdminCount == nil {
				t.Fatalf("known flags must be sent: %+v", got)
			}
			if got.GetBuiltinAdministrator() != tc.wantBuiltin || got.GetAdminCount() != tc.wantAdmin {
				t.Fatalf("flags = (builtin %v, adminCount %v), want (%v, %v)",
					got.GetBuiltinAdministrator(), got.GetAdminCount(), tc.wantBuiltin, tc.wantAdmin)
			}
		})
	}
}

func TestHeartbeatLeavesUnknownFlagsUnset(t *testing.T) {
	const protocol = "worker-flags-unknown"
	adapter.Register(protocol, &flagAdapter{fakeAdapter: fakeAdapter{result: adapter.Invalid}})
	fc := &fakeVaultClient{jobs: []*vaultv1.HeartbeatJob{heartbeatJob(protocol)}}

	runOnce(fc)

	got := fc.reports[0]
	if got.GetResult() != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED {
		t.Fatalf("result = %v, want FAILED", got.GetResult())
	}
	if got.BuiltinAdministrator != nil || got.AdminCount != nil {
		t.Fatalf("unknown flags must stay unset: %+v", got)
	}
}

func TestRotationOfBuiltinAdministratorIsReportedSkippedWithoutValidate(t *testing.T) {
	const protocol = "worker-rotate-builtin"
	fa := &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Refused, rotateDetail: adapter.BuiltinAdministratorReason}
	adapter.Register(protocol, fa)
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-rid500",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.ad.example.org", Port: 636, UseTls: true},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org"},
	}}}

	runOnce(fc)

	if fa.called {
		t.Fatal("nothing was changed, so nothing may be validated")
	}
	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	got := fc.rotationReports[0]
	if got.GetChange() != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED || got.GetValidate() != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		t.Fatalf("phases = (%v, %v), want (SKIPPED, SKIPPED)", got.GetChange(), got.GetValidate())
	}
	if got.BuiltinAdministrator == nil || !got.GetBuiltinAdministrator() {
		t.Fatalf("builtin_administrator must be true: %+v", got)
	}
	if got.GetDetail() != adapter.BuiltinAdministratorReason {
		t.Fatalf("detail = %q, want %q", got.GetDetail(), adapter.BuiltinAdministratorReason)
	}
	if got.GetVersion() != 7 {
		t.Fatalf("version = %d, want 7 so vault discards the staged credential", got.GetVersion())
	}
}

func TestRotationReportsLeaveBuiltinAdministratorUnsetOtherwise(t *testing.T) {
	const protocol = "worker-rotate-normal-flag"
	adapter.Register(protocol, &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid})
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{{
		SecretId:   "sec-normal",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.ad.example.org", Port: 636, UseTls: true},
	}}}

	runOnce(fc)

	if got := fc.rotationReports[0]; got.BuiltinAdministrator != nil {
		t.Fatalf("builtin_administrator must be unset on a normal rotation: %+v", got)
	}
}
