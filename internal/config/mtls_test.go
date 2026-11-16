// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	mtls "github.com/Bugs5382/go-mtls"
)

func setMTLS(t *testing.T, cert, key, ca, healthPort string) {
	t.Helper()
	t.Setenv("MTLS_CERT_FILE", cert)
	t.Setenv("MTLS_KEY_FILE", key)
	t.Setenv("MTLS_CA_FILE", ca)
	t.Setenv("HEALTH_PORT", healthPort)
	t.Setenv("MTLS_HEALTH_PORT", "")
}

func TestLoadMTLSIsOffWhenNothingIsSet(t *testing.T) {
	setMTLS(t, "", "", "", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.MTLSEnabled {
		t.Fatal("mTLS on with no files set")
	}
	if c.HealthPort != "9091" {
		t.Fatalf("HealthPort = %q, want the default 9091", c.HealthPort)
	}
}

func TestLoadMTLSReadsTheFilesAndTheHealthPort(t *testing.T) {
	setMTLS(t, "/etc/mtls/tls.crt", "/etc/mtls/tls.key", "/etc/mtls/ca.crt", "9190")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !c.MTLSEnabled {
		t.Fatal("mTLS off with all three files set")
	}
	want := mtls.Files{Cert: "/etc/mtls/tls.crt", Key: "/etc/mtls/tls.key", CA: "/etc/mtls/ca.crt"}
	if c.MTLSFiles != want {
		t.Fatalf("MTLSFiles = %+v, want %+v", c.MTLSFiles, want)
	}
	if c.HealthPort != "9190" {
		t.Fatalf("HealthPort = %q", c.HealthPort)
	}
}

func TestLoadMTLSPartialConfigurationStopsTheStart(t *testing.T) {
	setMTLS(t, "/etc/mtls/tls.crt", "", "/etc/mtls/ca.crt", "9190")
	_, err := Load()
	if err == nil {
		t.Fatal("two of three files set loaded without error")
	}
	if !strings.Contains(err.Error(), "MTLS_KEY_FILE") {
		t.Fatalf("error does not name the missing variable: %v", err)
	}
}

func TestLoadMTLSHealthPortDefaultsTo9091(t *testing.T) {
	setMTLS(t, "/etc/mtls/tls.crt", "/etc/mtls/tls.key", "/etc/mtls/ca.crt", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.HealthPort != "9091" {
		t.Fatalf("HealthPort = %q, want 9091", c.HealthPort)
	}
}

func TestLoadMTLSHealthPortFallsBackToTheOldName(t *testing.T) {
	setMTLS(t, "/etc/mtls/tls.crt", "/etc/mtls/tls.key", "/etc/mtls/ca.crt", "")
	t.Setenv("MTLS_HEALTH_PORT", "9290")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.HealthPort != "9290" {
		t.Fatalf("HealthPort = %q, want the MTLS_HEALTH_PORT value 9290", c.HealthPort)
	}
}

func TestLoadMTLSHealthPortWinsOverTheOldName(t *testing.T) {
	setMTLS(t, "/etc/mtls/tls.crt", "/etc/mtls/tls.key", "/etc/mtls/ca.crt", "9190")
	t.Setenv("MTLS_HEALTH_PORT", "9290")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.HealthPort != "9190" {
		t.Fatalf("HealthPort = %q, want HEALTH_PORT to win", c.HealthPort)
	}
}

func TestLoadMTLSHealthPortCannotBeTheGRPCPort(t *testing.T) {
	t.Setenv("GRPC_PORT", "9090")
	setMTLS(t, "/etc/mtls/tls.crt", "/etc/mtls/tls.key", "/etc/mtls/ca.crt", "9090")
	if _, err := Load(); err == nil {
		t.Fatal("HEALTH_PORT equal to GRPC_PORT loaded without error")
	}
}
