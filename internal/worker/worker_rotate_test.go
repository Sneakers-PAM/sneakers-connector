// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// TestRunClaimsRevealsRotatesValidatesReportsInSequence drives one due
// rotation job through Run end-to-end: ClaimDueRotations -> RevealForRotation
// -> adapter.Rotate(current, new) -> adapter.Validate(new) -> ReportRotation
// with the observed (change, validate) phases.
func TestRunClaimsRevealsRotatesValidatesReportsInSequence(t *testing.T) {
	const protocol = "worker-rotate-test-valid"
	fa := &fakeAdapter{result: adapter.Valid, rotateResult: adapter.Valid}
	adapter.Register(protocol, fa)

	job := &vaultv1.RotationJob{
		SecretId: "sec-rot-1",
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
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if fc.rotationClaimedLimit != rotationClaimLimit {
		t.Fatalf("rotation claim limit = %d, want %d", fc.rotationClaimedLimit, rotationClaimLimit)
	}
	if len(fc.revealedRotations) != 1 || fc.revealedRotations[0] != "sec-rot-1" {
		t.Fatalf("revealedRotations = %v, want [sec-rot-1]", fc.revealedRotations)
	}
	if !fa.rotateCalled {
		t.Fatal("adapter.Rotate was never called")
	}
	if fa.gotRotateCurrent.Username != "svc-example" || fa.gotRotateCurrent.Password != "hunter2" {
		t.Fatalf("rotate current cred = %+v, want the revealed username/current_password", fa.gotRotateCurrent)
	}
	if fa.gotNewPassword != "hunter3" {
		t.Fatalf("rotate newPassword = %q, want the revealed new_password", fa.gotNewPassword)
	}
	if !fa.called {
		t.Fatal("adapter.Validate was never called after a successful Rotate")
	}
	if fa.gotCred.Username != "svc-example" || fa.gotCred.Password != "hunter3" {
		t.Fatalf("post-rotation validate cred = %+v, want username + the NEW password", fa.gotCred)
	}

	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	got := fc.rotationReports[0]
	if got.GetSecretId() != "sec-rot-1" {
		t.Fatalf("report secret id = %q, want sec-rot-1", got.GetSecretId())
	}
	if got.GetChange() != vaultv1.RotationPhase_ROTATION_PHASE_OK {
		t.Fatalf("report change = %v, want OK", got.GetChange())
	}
	if got.GetValidate() != vaultv1.RotationPhase_ROTATION_PHASE_OK {
		t.Fatalf("report validate = %v, want OK", got.GetValidate())
	}
	if got.GetVersion() != 7 {
		t.Fatalf("report version = %d, want 7 (carried from the reveal)", got.GetVersion())
	}
}

// TestRunRotationChangeFailureSkipsValidate proves a failed change (target
// unchanged) is reported without ever calling Validate: there is nothing
// safe to validate, and the vault must keep the OLD credential active.
func TestRunRotationChangeFailureSkipsValidate(t *testing.T) {
	const protocol = "worker-rotate-test-change-invalid"
	fa := &fakeAdapter{rotateResult: adapter.Invalid, rotateDetail: "invalid credentials"}
	adapter.Register(protocol, fa)

	job := &vaultv1.RotationJob{
		SecretId:   "sec-rot-2",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.ad.example.org", Port: 636},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if fa.called {
		t.Fatal("adapter.Validate was called after a failed Rotate, want it skipped")
	}
	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	got := fc.rotationReports[0]
	if got.GetChange() != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Fatalf("report change = %v, want FAILED", got.GetChange())
	}
	if got.GetValidate() != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		t.Fatalf("report validate = %v, want SKIPPED", got.GetValidate())
	}
	if got.GetDetail() != "invalid credentials" {
		t.Fatalf("report detail = %q, want the adapter's Rotate detail", got.GetDetail())
	}
}

// TestRunRotationUnreachableChangeIsFailed proves Unreachable, like
// Invalid, maps to FAILED for the change phase (unlike heartbeat, rotation
// has no distinct UNREACHABLE phase: an unconfirmed change is a failure).
func TestRunRotationUnreachableChangeIsFailed(t *testing.T) {
	const protocol = "worker-rotate-test-change-unreachable"
	fa := &fakeAdapter{rotateResult: adapter.Unreachable, rotateDetail: "dial tcp: no route to host"}
	adapter.Register(protocol, fa)

	job := &vaultv1.RotationJob{
		SecretId:   "sec-rot-3",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "unreachable.ad.example.org", Port: 636},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	if got := fc.rotationReports[0].GetChange(); got != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Fatalf("report change = %v, want FAILED", got)
	}
}

// TestRunRotationDegradedWhenValidateFails proves the change-ok/validate-
// failed branch: the report still carries change=OK (the target DOES have
// the new password) alongside validate=FAILED, so the vault can commit and
// mark the secret degraded rather than desyncing.
func TestRunRotationDegradedWhenValidateFails(t *testing.T) {
	const protocol = "worker-rotate-test-degraded"
	fa := &fakeAdapter{
		rotateResult: adapter.Valid,
		result:       adapter.Unreachable,
		detail:       "validate: no route to host",
	}
	adapter.Register(protocol, fa)

	job := &vaultv1.RotationJob{
		SecretId:   "sec-rot-4",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "dc1.ad.example.org", Port: 636},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	got := fc.rotationReports[0]
	if got.GetChange() != vaultv1.RotationPhase_ROTATION_PHASE_OK {
		t.Fatalf("report change = %v, want OK", got.GetChange())
	}
	if got.GetValidate() != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Fatalf("report validate = %v, want FAILED", got.GetValidate())
	}
}

// TestRunRotationPrefersKerberosValidateWhenRealmSet proves that when the
// target has a realm, post-rotation validation goes through the kerberos
// adapter (which invalidates immediately) rather than the adapter that performed the change (whose
// LDAP simple-bind may still honor the OLD password during a grace
// window), even though the change itself went through the ldap-registered
// protocol. It uses the real "kerberos" adapter (registered by the adapter
// package's own init()) rather than swapping in a fake, so as not to
// mutate global adapter registry state other tests in this binary may
// depend on; a dead port makes the real kerberos adapter's outcome
// (Unreachable -> FAILED) deterministic without a live KDC.
func TestRunRotationPrefersKerberosValidateWhenRealmSet(t *testing.T) {
	const protocol = "worker-rotate-test-prefers-kerberos"
	changeAdapter := &fakeAdapter{rotateResult: adapter.Valid, result: adapter.Invalid, detail: "ldap would wrongly say ok"}
	adapter.Register(protocol, changeAdapter)

	job := &vaultv1.RotationJob{
		SecretId:   "sec-rot-5",
		Connection: &vaultv1.HeartbeatConn{Protocol: protocol, Host: "127.0.0.1", Port: 1},
		Target:     &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org", Realm: "AD.EXAMPLE.ORG"},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if changeAdapter.called {
		t.Fatal("the change adapter's Validate was called, want the kerberos adapter to have been used instead (Realm is set)")
	}
	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	// The real kerberos adapter can't reach 127.0.0.1:1, so it reports
	// Unreachable -> FAILED; that's the point: if changeAdapter (which
	// would have said Invalid, still mapping to FAILED) had been used
	// instead, this assertion alone wouldn't distinguish them, which is
	// why changeAdapter.called is the primary assertion above.
	if got := fc.rotationReports[0].GetValidate(); got != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Fatalf("report validate = %v, want FAILED", got)
	}
}

// TestRunRotationKerberosValidateGetsPortZero is a regression guard:
// when validation is routed to the kerberos adapter (Realm set), the Conn
// it receives must NOT carry the LDAPS port used to perform the change --
// reusing that port sends the AS-REQ nowhere a KDC listens, so validation
// (and therefore every realm-backed rotation) would always report
// Unreachable/DEGRADED. It swaps a fake in for the globally-registered
// "kerberos" adapter (restored via defer) so the exact Conn can be
// inspected, rather than relying on the real adapter's Unreachable outcome
// as TestRunRotationPrefersKerberosValidateWhenRealmSet does.
func TestRunRotationKerberosValidateGetsPortZero(t *testing.T) {
	origKerberos, ok := adapter.Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered (adapter package init)")
	}
	fakeKerberos := &fakeAdapter{result: adapter.Valid}
	adapter.Register("kerberos", fakeKerberos)
	defer adapter.Register("kerberos", origKerberos)

	const protocol = "worker-rotate-test-kerberos-port"
	changeAdapter := &fakeAdapter{rotateResult: adapter.Valid}
	adapter.Register(protocol, changeAdapter)

	job := &vaultv1.RotationJob{
		SecretId: "sec-rot-8",
		Connection: &vaultv1.HeartbeatConn{
			Protocol: protocol,
			Host:     "dc1.ad.example.org",
			Port:     636,
			UseTls:   true,
		},
		Target: &vaultv1.HeartbeatTarget{Kind: "ad", Domain: "ad.example.org", Realm: "AD.EXAMPLE.ORG"},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc)

	if !fakeKerberos.called {
		t.Fatal("the swapped-in kerberos adapter's Validate was never called")
	}
	if fakeKerberos.gotConn.Port != 0 {
		t.Fatalf("kerberos validate Conn.Port = %d, want 0 (not the LDAPS port %d), so kerberosAdapter.Validate falls back to its own default KDC port", fakeKerberos.gotConn.Port, 636)
	}
	if fakeKerberos.gotConn.Host != "dc1.ad.example.org" {
		t.Fatalf("kerberos validate Conn.Host = %q, want dc1.ad.example.org (only Port should be reset)", fakeKerberos.gotConn.Host)
	}
	if changeAdapter.gotRotateConn.Port != 636 {
		t.Fatalf("change adapter's Rotate Conn.Port = %d, want 636 (the change adapter's Conn must be untouched)", changeAdapter.gotRotateConn.Port)
	}
}

// TestRunRotationSkipsForUnregisteredProtocol proves an unhandled rotation
// job is still reported (SKIPPED for both phases), not silently dropped,
// and that no reveal is attempted for it.
func TestRunRotationSkipsForUnregisteredProtocol(t *testing.T) {
	job := &vaultv1.RotationJob{
		SecretId:   "sec-rot-6",
		Connection: &vaultv1.HeartbeatConn{Protocol: "worker-rotate-test-unregistered-protocol"},
	}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc) // must not panic

	if len(fc.revealedRotations) != 0 {
		t.Fatalf("revealedRotations = %v, want none (adapter missing, no reveal attempted)", fc.revealedRotations)
	}
	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1 (unhandled job must still be reported, not skipped silently)", len(fc.rotationReports))
	}
	got := fc.rotationReports[0]
	if got.GetChange() != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		t.Fatalf("report change = %v, want SKIPPED", got.GetChange())
	}
	if got.GetValidate() != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		t.Fatalf("report validate = %v, want SKIPPED", got.GetValidate())
	}
	if got.GetDetail() == "" {
		t.Fatal("detail = \"\", want a message naming the unregistered protocol")
	}
	if got.GetVersion() != 0 {
		t.Fatalf("report version = %d, want 0 (reported SKIPPED before any reveal)", got.GetVersion())
	}
}

// TestRunRotationSkipsForNilConnection mirrors the heartbeat nil-connection
// guard: a job with no Connection can never be rotated, so it's reported
// SKIPPED, not dropped.
func TestRunRotationSkipsForNilConnection(t *testing.T) {
	job := &vaultv1.RotationJob{SecretId: "sec-rot-7", Connection: nil}
	fc := &fakeVaultClient{rotationJobs: []*vaultv1.RotationJob{job}}

	runOnce(fc) // must not panic

	if len(fc.revealedRotations) != 0 {
		t.Fatalf("revealedRotations = %v, want none (nil connection, no reveal attempted)", fc.revealedRotations)
	}
	if len(fc.rotationReports) != 1 {
		t.Fatalf("rotation reports = %d, want 1", len(fc.rotationReports))
	}
	if got := fc.rotationReports[0].GetChange(); got != vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED {
		t.Fatalf("report change = %v, want SKIPPED", got)
	}
}

// TestToRotationPhaseMapping is a table test of the pure mapping helper.
func TestToRotationPhaseMapping(t *testing.T) {
	cases := []struct {
		in   adapter.Result
		want vaultv1.RotationPhase
	}{
		{adapter.Valid, vaultv1.RotationPhase_ROTATION_PHASE_OK},
		{adapter.Invalid, vaultv1.RotationPhase_ROTATION_PHASE_FAILED},
		{adapter.Unreachable, vaultv1.RotationPhase_ROTATION_PHASE_FAILED},
	}
	for _, c := range cases {
		if got := toRotationPhase(c.in); got != c.want {
			t.Errorf("toRotationPhase(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestValidateAdapterForPrefersKerberosOnlyWithRealm is a table test of the
// pure selection helper backing the prefer-Kerberos-when-a-realm-is-set rule.
func TestValidateAdapterForPrefersKerberosOnlyWithRealm(t *testing.T) {
	changeAdapter := &fakeAdapter{}
	kAdapter, ok := adapter.Get("kerberos")
	if !ok {
		t.Fatal("kerberos adapter not registered (adapter package init)")
	}

	if got := validateAdapterFor(changeAdapter, ""); got != changeAdapter {
		t.Fatal("validateAdapterFor with no realm should return changeAdapter")
	}
	if got := validateAdapterFor(changeAdapter, "AD.EXAMPLE.ORG"); got != kAdapter {
		t.Fatal("validateAdapterFor with a realm should return the registered kerberos adapter")
	}
}
