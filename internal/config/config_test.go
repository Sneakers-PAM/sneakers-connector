// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
)

// TestLoadNoDatabaseDSN covers #22: the connector has no database, so Load
// must not require DATABASE_DSN (or read it at all) to start.
func TestLoadNoDatabaseDSN(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err with no env set: %v", err)
	}
	if c.GRPCPort != "9090" {
		t.Fatalf("default GRPCPort got %q", c.GRPCPort)
	}
}

// TestLoadOTLPEndpointUnsetStaysEmpty covers #35: an unset or empty
// OTEL_EXPORTER_OTLP_ENDPOINT must reach go-otel's Init as "", which it
// treats as export-off, not as a localhost:4317 default nothing is
// listening on.
func TestLoadOTLPEndpointUnsetStaysEmpty(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.OTLPEndpoint != "" {
		t.Fatalf("default OTLPEndpoint got %q, want empty", c.OTLPEndpoint)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317")
	c, err = Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.OTLPEndpoint != "collector:4317" {
		t.Fatalf("OTLPEndpoint passthrough got %q", c.OTLPEndpoint)
	}
}
