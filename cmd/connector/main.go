// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-connector/internal/config"
	"github.com/Sneakers-PAM/sneakers-connector/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
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

	otelShutdown, err := otel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	vc, err := vaultclient.Dial()
	if err != nil {
		logger.Fatal().Err(err).Msg("dial vault")
	}
	defer func() { _ = vc.Close() }()

	tokens, err := tokensource.FromEnv(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("connector token source")
	}

	svcLog := log.NewLogger(serviceName)
	go worker.RunWithLogger(ctx, vc, tokens, pollInterval, svcLog)

	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")

	// TODO: when the connector gains mutating RPCs of its own, wire an audit
	// emitter here and pass it to the grpcsvc constructors, so every mutation
	// emits an audit event.
	// Readiness follows the vault: every job the worker runs is claimed from
	// it and reported back to it. Liveness never asks.
	checker, err := server.NewChecker(svcLog, []health.Dependency{server.Vault(vc.Conn())})
	if err != nil {
		logger.Fatal().Err(err).Msg("health checker")
	}
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, svcLog, checker, func(gs *grpc.Server) {
		grpcsvc.Register(gs)
	}); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
