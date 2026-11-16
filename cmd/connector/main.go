// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-connector/internal/config"
	"github.com/Sneakers-PAM/sneakers-connector/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
	"github.com/Sneakers-PAM/sneakers-connector/internal/telemetry"
	"github.com/Sneakers-PAM/sneakers-connector/internal/tokensource"
	"github.com/Sneakers-PAM/sneakers-connector/internal/vaultclient"
	"github.com/Sneakers-PAM/sneakers-connector/internal/worker"
	"google.golang.org/grpc"
)

const serviceName = "connector"

// pollInterval bounds how often the worker polls the vault for due
// heartbeat jobs.
const pollInterval = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}

	tel := telemetry.Load(cfg.OTLPEndpoint)
	logger = tel.Zerolog(logger, os.Stdout)
	svcLog := log.NewLoggerWithOptions(serviceName, log.WithOutput(tel.Output(os.Stdout)))

	otelShutdown, err := otel.InitWithOptions(ctx, serviceName, cfg.OTLPEndpoint, tel.Options()...)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	// Mutual TLS is on when the three MTLS_* files are set (config.Load stops
	// a partial setting). The same provider serves the gRPC port and dials
	// the vault; with none set both stay plaintext, as before.
	var (
		dialOpts   []grpc.DialOption
		serverOpts []grpc.ServerOption
	)
	if cfg.MTLSEnabled {
		mp, err := mtls.NewProvider(cfg.MTLSFiles, mtls.WithErrorHandler(func(err error) {
			svcLog.Error(err, "mtls: certificate reload failed; the last good certificate stays in use")
		}))
		if err != nil {
			logger.Fatal().Err(err).Msg("mtls files")
		}
		dialOpts = append(dialOpts, mp.DialOption())
		serverOpts = append(serverOpts, mp.ServerOption())
		svcLog.Info("mutual TLS on", log.F("grpc_port", cfg.GRPCPort), log.F("health_port", cfg.HealthPort))
	} else {
		svcLog.Info("mutual TLS off: the gRPC port and the vault connection are plaintext")
	}

	vc, err := vaultclient.Dial(svcLog, dialOpts...)
	if err != nil {
		logger.Fatal().Err(err).Msg("dial vault")
	}
	defer func() { _ = vc.Close() }()

	tokens, err := tokensource.FromEnv(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("connector token source")
	}

	go worker.RunWithLogger(ctx, vc, tokens, pollInterval, svcLog)

	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")

	// TODO: when the connector gains mutating RPCs of its own, wire an audit
	// emitter here and pass it to the grpcsvc constructors, so every mutation
	// emits an audit event.
	// Readiness follows the vault: every job the worker runs is claimed from
	// it and reported back to it. Liveness never asks.
	deps := append([]health.Dependency{server.Vault(vc.Conn())}, tel.Dependencies()...)
	mode, authOpts, verifierDep := inboundAuth(ctx, svcLog)
	if verifierDep != nil {
		deps = append(deps, *verifierDep)
	}
	checker, err := server.NewChecker(svcLog, deps)
	if err != nil {
		logger.Fatal().Err(err).Msg("health checker")
	}
	if err := server.RunWithHealthPort(ctx, cfg.GRPCPort, cfg.HealthPort, svcLog, checker, func(gs *grpc.Server) {
		grpcsvc.Register(gs)
		if mode != server.InboundOff {
			grpcsvc.RegisterTLSScan(gs, grpcsvc.NewTLSScanServer(svcLog))
		}
	}, append(serverOpts, authOpts...)...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
