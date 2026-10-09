// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
)

type Config struct {
	GRPCPort     string
	OTLPEndpoint string
}

func Load() (Config, error) {
	c := Config{
		GRPCPort:     getOr("GRPC_PORT", "9090"),
		OTLPEndpoint: getOr("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
	}
	return c, nil
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
