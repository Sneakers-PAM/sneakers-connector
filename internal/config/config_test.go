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
