// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry holds the connector's OTLP settings, the filters on what it
// exports, and the optional health dependency on the collector.
//
// The filters are a default-deny list. This service's error text comes from
// the systems it acts on and can echo a credential, so any field that can hold
// such text is exported as its class only.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Bugs5382/go-buildinfo/health"
	otel "github.com/Bugs5382/go-otel"
	"github.com/rs/zerolog"
)

const (
	// EnvSkipVerify turns off collector certificate checks when "true".
	EnvSkipVerify = "OTLP_INSECURE_SKIP_VERIFY"
	// EnvLogs turns on log export when "true".
	EnvLogs = "OTLP_LOGS_ENABLED"

	// DependencyName is the health dependency for the collector.
	DependencyName = "otlp"
)

// AllowedLogFields are the fields an exported log record may carry.
var AllowedLogFields = []string{
	"secret_id",
	"result",
	"error_code",
	"error_class",
	"backoff",
	"pinned_keys",
	"pinned_certificates",
	"builtin_administrator",
	"admin_count",
	"dependency",
	"required",
	"from",
	"to",
	"port",
	"error",
	"detail",
	"reason",
}

// ClassOnlyLogFields narrow AllowedLogFields to the value's class: they can
// hold a target system's text.
var ClassOnlyLogFields = []string{"error", "detail", "reason"}

// AllowedRPCAttributes are the attributes spans and metrics may carry. The
// connector serves and calls gRPC only, so it emits no HTTP attributes.
var AllowedRPCAttributes = []string{"rpc.method", "rpc.response.status_code"}

var (
	// rpcMethodPattern matches this service's own methods and the vault's.
	rpcMethodPattern = regexp.MustCompile(`^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$`)
	// healthMethodPattern matches the probes and the vault health check.
	healthMethodPattern = regexp.MustCompile(`^grpc\.health\.v1\.Health/(Check|Watch)$`)
)

var tokenPattern = regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)

// Settings is the OTLP configuration from the environment.
type Settings struct {
	Endpoint   string
	SkipVerify bool
	Logs       bool
}

// Load reads the OTLP switches from the environment. Only the exact value
// "true" turns one on.
func Load(endpoint string) Settings {
	return Settings{
		Endpoint:   endpoint,
		SkipVerify: os.Getenv(EnvSkipVerify) == "true",
		Logs:       os.Getenv(EnvLogs) == "true",
	}
}

// Options returns the go-otel options for s.
func (s Settings) Options() []otel.Option {
	return []otel.Option{
		otel.WithInsecureSkipVerify(s.SkipVerify),
		otel.WithTelemetryFilter(true),
		otel.WithTraceAllowSpanNames(rpcMethodPattern, healthMethodPattern),
		otel.WithAttributeValuePattern("rpc.method", rpcMethodPattern),
		otel.WithTraceAllowAttributes(AllowedRPCAttributes...),
		otel.WithMetricAllowAttributes(AllowedRPCAttributes...),
		otel.WithBaggage(false),
		otel.WithLogs(s.Logs),
		otel.WithLogAllowFields(AllowedLogFields...),
		otel.WithLogClassOnlyFields(ClassOnlyLogFields...),
		otel.WithLogRedactPatterns(tokenPattern),
	}
}

// Output returns stdout, teed to the log exporter when logs are on.
func (s Settings) Output(stdout io.Writer) io.Writer {
	if !s.Logs {
		return stdout
	}
	return io.MultiWriter(stdout, otel.LogWriter())
}

// Zerolog points l at Output when logs are on. Only the JSON formats change:
// Output replaces l's writer, which would undo console rendering, and the
// exporter reads JSON only.
func (s Settings) Zerolog(l zerolog.Logger, stdout io.Writer) zerolog.Logger {
	if !s.Logs {
		return l
	}
	switch strings.ToLower(os.Getenv("LOG_FORMAT")) {
	case "console", "pretty", "both":
		return l
	}
	return l.Output(s.Output(stdout))
}

// ErrExportFailing is the otlp dependency's error. It holds no collector text.
var ErrExportFailing = errors.New("otlp export failing")

// Check fails when a signal's last export error is newer than its last
// success. Logs count only when logsOn.
func Check(state otel.ExportStatus, logsOn bool) error {
	signals := []otel.SignalStatus{state.Traces, state.Metrics}
	if logsOn {
		signals = append(signals, state.Logs)
	}
	for _, s := range signals {
		if s.LastErrorAt.After(s.LastSuccess) {
			return health.Classify(ErrExportFailing, "unavailable")
		}
	}
	return nil
}

// Dependencies returns the optional otlp dependency, or none with no endpoint.
func (s Settings) Dependencies() []health.Dependency {
	if strings.TrimSpace(s.Endpoint) == "" {
		return nil
	}
	return []health.Dependency{{
		Name:     DependencyName,
		Required: false,
		Check: func(context.Context) error {
			return Check(otel.ExportState(), s.Logs)
		},
	}}
}
