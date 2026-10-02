// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package worker implements the connector's poll loops: one claims due
// heartbeat jobs from the vault, reveals the managed credential for each,
// validates it against the target via the protocol adapter registry, and
// reports the outcome back to the vault; the other does the same for due
// rotation jobs, additionally calling adapter.Rotate to change the
// credential on the target before validating the new one.
package worker

import (
	"context"
	"fmt"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// claimLimit bounds how many due heartbeat jobs are claimed per tick.
const claimLimit = 20

// jobTimeout bounds how long a single heartbeat job's reveal/validate/report
// RPCs may take, so one slow or hung target can't stall the rest of a
// serial batch past the vault's claim window.
const jobTimeout = 20 * time.Second

// rotJobTimeout bounds a single rotation job's reveal/rotate/validate/report
// RPCs. It's longer than jobTimeout because a rotation does strictly more
// work per job (a write plus a validate, vs. just a validate).
const rotJobTimeout = 30 * time.Second

// Run polls vc for due heartbeat jobs and due rotation jobs, processing each
// and reporting the result back to the vault, until ctx is cancelled. It
// performs one poll of each immediately (rather than waiting a full
// interval on startup) and then polls again every interval, rotation always
// following heartbeat within the same tick. A single job's failure is
// handled best-effort and never aborts the rest of the tick.
func Run(ctx context.Context, vc vaultv1.VaultServiceClient, token string, interval time.Duration) {
	RunWithSource(ctx, vc, staticToken(token), interval)
}

// TokenSource supplies the worker-identity token presented to the vault.
type TokenSource interface {
	Token() string
}

type staticToken string

func (s staticToken) Token() string { return string(s) }

// RunWithSource is Run with the token taken from src at the start of every
// tick, so a token rotated underneath the connector is presented on the
// next poll without a restart.
func RunWithSource(ctx context.Context, vc vaultv1.VaultServiceClient, src TokenSource, interval time.Duration) {
	runTicks(ctx, vc, src)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runTicks(ctx, vc, src)
		}
	}
}

func runTicks(ctx context.Context, vc vaultv1.VaultServiceClient, src TokenSource) {
	identity := &vaultv1.WorkerIdentity{Token: src.Token()}
	tick(ctx, vc, identity)
	rotationTick(ctx, vc, identity)
}

// tick claims one batch of due jobs and processes each best-effort.
func tick(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity) {
	logger := log.Ctx(ctx)

	resp, err := vc.ClaimDueHeartbeats(ctx, &vaultv1.ClaimDueHeartbeatsRequest{
		Identity: identity,
		Limit:    claimLimit,
	})
	if err != nil {
		logger.Warn().Err(err).Msg("claim due heartbeats")
		return
	}

	for _, job := range resp.GetJobs() {
		processJob(ctx, vc, identity, job)
	}
}

// processJob picks the adapter for job's protocol, reveals the managed
// credential, validates it against the target, and reports the outcome.
// A job whose protocol has no registered adapter (or whose connection is
// missing) can never be validated, so it is reported UNREACHABLE rather
// than silently skipped: the vault only advances a secret's schedule when
// it receives a report, and a report-less skip would leave the job due
// forever, re-claimed and re-skipped on every tick. Any other failure along
// the way is logged and the job is abandoned for this tick (it will be
// reclaimed on a future poll) rather than aborting the batch. Reveal and
// validate are bounded by jobTimeout so one slow target can't stall the
// rest of a serial batch.
func processJob(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity, job *vaultv1.HeartbeatJob) {
	logger := log.Ctx(ctx).With().Str("secret_id", job.GetSecretId()).Logger()

	ctx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()

	protocol := job.GetConnection().GetProtocol()
	a, ok := adapter.Get(protocol)
	if !ok || job.GetConnection() == nil {
		detail := fmt.Sprintf("no adapter for protocol %q", protocol)
		logger.Warn().Str("protocol", protocol).Msg("no adapter registered for protocol; reporting unreachable")
		reportHeartbeat(ctx, vc, identity, job, vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE, detail, adapter.AccountFlags{})
		return
	}

	reveal, err := vc.RevealForHeartbeat(ctx, &vaultv1.RevealForHeartbeatRequest{
		Identity: identity,
		SecretId: job.GetSecretId(),
	})
	if err != nil {
		logger.Warn().Err(err).Msg("reveal for heartbeat")
		return
	}

	conn := adapter.Conn{
		Host:   job.GetConnection().GetHost(),
		Port:   int(job.GetConnection().GetPort()),
		UseTLS: job.GetConnection().GetUseTls(),
		Domain: job.GetTarget().GetDomain(),
		Realm:  job.GetTarget().GetRealm(),
	}
	cred := adapter.Cred{
		Username:   reveal.GetUsername(),
		Password:   reveal.GetPassword(),
		PrivateKey: reveal.GetPrivateKey(),
		Passphrase: reveal.GetPassphrase(),
	}

	var result adapter.Result
	var detail string
	var flags adapter.AccountFlags
	if av, ok := a.(adapter.AccountValidator); ok {
		result, detail, flags = av.ValidateAccount(ctx, conn, cred)
	} else {
		result, detail = a.Validate(ctx, conn, cred)
	}
	if flags.Known {
		logger.Debug().Bool("builtin_administrator", flags.BuiltinAdministrator).Bool("admin_count", flags.AdminCount).
			Msg("heartbeat read account flags")
	}

	reportHeartbeat(ctx, vc, identity, job, toHeartbeatResult(result), detail, flags)
}

// reportHeartbeat reports a job's outcome back to the vault, logging
// (without failing the batch) if the report RPC itself errors. Account
// flags are sent only when the adapter could read them.
func reportHeartbeat(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity, job *vaultv1.HeartbeatJob, result vaultv1.HeartbeatResult, detail string, flags adapter.AccountFlags) {
	req := &vaultv1.ReportHeartbeatRequest{
		Identity: identity,
		SecretId: job.GetSecretId(),
		Result:   result,
		Detail:   detail,
	}
	if flags.Known {
		req.BuiltinAdministrator = &flags.BuiltinAdministrator
		req.AdminCount = &flags.AdminCount
	}
	if _, err := vc.ReportHeartbeat(ctx, req); err != nil {
		logger := log.Ctx(ctx).With().Str("secret_id", job.GetSecretId()).Logger()
		logger.Warn().Err(err).Msg("report heartbeat")
	}
}

// toHeartbeatResult maps an adapter validation outcome onto the wire
// HeartbeatResult reported to the vault.
func toHeartbeatResult(r adapter.Result) vaultv1.HeartbeatResult {
	switch r {
	case adapter.Valid:
		return vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK
	case adapter.Invalid:
		return vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED
	case adapter.Unreachable:
		return vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE
	default:
		return vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN
	}
}

// rotationClaimLimit bounds how many due rotation jobs are claimed per
// tick. Rotation is heavier than heartbeat (a write plus a validate per
// job), but there's no reason yet to claim a different batch size, so it
// mirrors claimLimit.
const rotationClaimLimit = claimLimit

// rotationTick claims one batch of due rotation jobs and processes each
// best-effort.
func rotationTick(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity) {
	logger := log.Ctx(ctx)

	resp, err := vc.ClaimDueRotations(ctx, &vaultv1.ClaimDueRotationsRequest{
		Identity: identity,
		Limit:    rotationClaimLimit,
	})
	if err != nil {
		logger.Warn().Err(err).Msg("claim due rotations")
		return
	}

	for _, job := range resp.GetJobs() {
		processRotationJob(ctx, vc, identity, job)
	}
}

// processRotationJob picks the adapter for job's protocol, reveals the
// current and freshly-generated new credential, changes the password on
// the target via adapter.Rotate, and -- only if that change succeeded --
// validates the new password before reporting the two-phase outcome. A job
// whose protocol has no registered adapter (or whose connection is
// missing) is reported SKIPPED rather than silently dropped: like the
// heartbeat path, the vault only advances a secret's rotation schedule on
// report, so a report-less skip would leave the job due forever. A Refused
// change (the built-in Administrator) is reported SKIPPED with
// builtin_administrator set, so the vault discards the staged credential
// and stops scheduling the secret. Reveal failures are logged and the job is abandoned for this tick (reclaimed on
// a future poll) without a report, matching the heartbeat path.
//
// Post-rotation validation prefers Kerberos over the protocol that
// performed the change whenever the target has a realm: AD's LDAP
// simple-bind honors the OLD password for a grace window (NTLM), so an
// LDAP-bind validate right after a successful change can pass on the old
// password and mask a broken rotation, while Kerberos invalidates
// immediately and so proves the NEW password authoritatively.
func processRotationJob(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity, job *vaultv1.RotationJob) {
	logger := log.Ctx(ctx).With().Str("secret_id", job.GetSecretId()).Logger()

	ctx, cancel := context.WithTimeout(ctx, rotJobTimeout)
	defer cancel()

	protocol := job.GetConnection().GetProtocol()
	a, ok := adapter.Get(protocol)
	if !ok || job.GetConnection() == nil {
		detail := fmt.Sprintf("no adapter for protocol %q", protocol)
		logger.Warn().Str("protocol", protocol).Msg("no adapter registered for protocol; reporting rotation skipped")
		reportRotation(ctx, vc, identity, job, vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, detail, 0, false)
		return
	}

	reveal, err := vc.RevealForRotation(ctx, &vaultv1.RevealForRotationRequest{
		Identity: identity,
		SecretId: job.GetSecretId(),
	})
	if err != nil {
		logger.Warn().Err(err).Msg("reveal for rotation")
		return
	}
	version := reveal.GetVersion()

	conn := adapter.Conn{
		Host:   job.GetConnection().GetHost(),
		Port:   int(job.GetConnection().GetPort()),
		UseTLS: job.GetConnection().GetUseTls(),
		Domain: job.GetTarget().GetDomain(),
		Realm:  job.GetTarget().GetRealm(),
	}
	current := adapter.Cred{
		Username: reveal.GetUsername(),
		Password: reveal.GetCurrentPassword(),
	}
	newPassword := reveal.GetNewPassword()

	changeResult, changeDetail := a.Rotate(ctx, conn, current, newPassword)
	changePhase := toRotationPhase(changeResult)

	if changeResult == adapter.Refused {
		logger.Warn().Str("reason", changeDetail).Msg("rotation refused: built-in Administrator account; nothing changed")
		reportRotation(ctx, vc, identity, job, vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, changeDetail, version, true)
		return
	}
	if changeResult != adapter.Valid {
		// The target was never successfully changed: there is nothing to
		// validate, and the vault must keep the OLD credential active.
		reportRotation(ctx, vc, identity, job, changePhase, vaultv1.RotationPhase_ROTATION_PHASE_SKIPPED, changeDetail, version, false)
		return
	}

	va := validateAdapterFor(a, job.GetTarget().GetRealm())
	validateConn := conn
	if k, ok := adapter.Get("kerberos"); ok && va == k {
		// conn.Port is the LDAP/LDAPS port used to perform the change (e.g.
		// 636); the Kerberos adapter's KDC almost never listens there, so
		// reusing it makes the AS-REQ always Unreachable. Reset Port to 0
		// (a copy -- conn itself, used by the change adapter above, must
		// stay untouched) so kerberosAdapter.Validate falls back to its own
		// default KDC port (88).
		//
		// Known limitation: Conn has only one Port field, shared between
		// the change adapter and this validate adapter, so a non-standard
		// KDC port can't be expressed here.
		validateConn.Port = 0
	}
	validateResult, validateDetail := va.Validate(ctx, validateConn, adapter.Cred{Username: current.Username, Password: newPassword})
	validatePhase := toRotationPhase(validateResult)

	detail := validateDetail
	if detail == "" {
		detail = changeDetail
	}
	reportRotation(ctx, vc, identity, job, changePhase, validatePhase, detail, version, false)
}

// validateAdapterFor picks the adapter used to validate the freshly-rotated
// password (see processRotationJob's doc comment for the rationale): when
// the target has a realm and a kerberos adapter is registered, it wins over
// changeAdapter (the adapter that performed the change, e.g. ldap).
func validateAdapterFor(changeAdapter adapter.Adapter, realm string) adapter.Adapter {
	if realm == "" {
		return changeAdapter
	}
	if k, ok := adapter.Get("kerberos"); ok {
		return k
	}
	return changeAdapter
}

// reportRotation reports a job's two-phase outcome back to the vault,
// logging (without failing the batch) if the report RPC itself errors.
// version is the staged secret version captured from the preceding
// RevealForRotation call (RevealForRotationResponse.GetVersion()), so the
// vault can commit the exact applied version idempotently; callers that
// report without ever having revealed (e.g. no adapter or nil connection,
// reported SKIPPED before any reveal) pass 0, which the vault handles
// defensively. builtinAdmin marks a refusal of the built-in Administrator so
// the vault stops scheduling it; otherwise the field is left unset.
func reportRotation(ctx context.Context, vc vaultv1.VaultServiceClient, identity *vaultv1.WorkerIdentity, job *vaultv1.RotationJob, change, validate vaultv1.RotationPhase, detail string, version int32, builtinAdmin bool) {
	req := &vaultv1.ReportRotationRequest{
		Identity: identity,
		SecretId: job.GetSecretId(),
		Change:   change,
		Validate: validate,
		Detail:   detail,
		Version:  version,
	}
	if builtinAdmin {
		req.BuiltinAdministrator = &builtinAdmin
	}
	if _, err := vc.ReportRotation(ctx, req); err != nil {
		logger := log.Ctx(ctx).With().Str("secret_id", job.GetSecretId()).Logger()
		logger.Warn().Err(err).Msg("report rotation")
	}
}

// toRotationPhase maps an adapter outcome onto the wire RotationPhase
// reported to the vault. Unlike toHeartbeatResult, Invalid and Unreachable
// both map to FAILED: for rotation, a change or validation that couldn't be
// confirmed successful is a failure either way (the vault must not treat an
// unreachable target as proof of anything), never its own distinct phase.
func toRotationPhase(r adapter.Result) vaultv1.RotationPhase {
	switch r {
	case adapter.Valid:
		return vaultv1.RotationPhase_ROTATION_PHASE_OK
	case adapter.Invalid, adapter.Unreachable:
		return vaultv1.RotationPhase_ROTATION_PHASE_FAILED
	default:
		return vaultv1.RotationPhase_ROTATION_PHASE_UNSPECIFIED
	}
}
