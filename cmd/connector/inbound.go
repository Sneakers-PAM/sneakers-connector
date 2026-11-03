// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"

	"github.com/Sneakers-PAM/sneakers-connector/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
)

// inboundAuth decides how the connector's own API (the TLS scan) is served,
// from the WORKLOAD_* variables. With no issuer the scan isn't served and the
// connector starts as before, with its health services only. A malformed
// setting stops the start. When callers are verified it returns the
// interceptors and the readiness dependency on the verifier's key set.
func inboundAuth(ctx context.Context, lg log.Logger) (server.InboundMode, []grpc.ServerOption, *health.Dependency) {
	cfg, mode, err := server.WorkloadConfigFromEnv(os.Getenv)
	if err != nil {
		lg.Fatal(err, "workload authentication")
	}
	switch mode {
	case server.InboundOff:
		lg.Warn("TLS certificate scan off: " + workloadauth.EnvIssuer + " is unset, so the connector serves its health services only")
		return mode, nil, nil
	case server.InboundDisabled:
		go workloadauth.WarnDisabled(ctx, lg, workloadauth.DisabledWarnInterval)
		lg.Info("TLS certificate scan on, with caller authentication disabled")
		return mode, nil, nil
	}
	v, err := workloadauth.NewVerifier(cfg, lg)
	if err != nil {
		lg.Fatal(err, "workload verifier")
	}
	go v.Run(ctx)
	lg.Info("TLS certificate scan on; only the gateway may call it",
		log.F("issuer", cfg.Issuer), log.F("allowed", cfg.AllowedServiceAccounts))
	dep := server.WorkloadIdentity(v)
	return mode, grpcsvc.AuthServerOptions(v, lg), &dep
}
