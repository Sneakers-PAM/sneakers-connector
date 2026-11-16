// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"

	mtls "github.com/Bugs5382/go-mtls"
)

type Config struct {
	GRPCPort     string
	OTLPEndpoint string

	// MTLSEnabled is true when the three go-mtls files (MTLS_CERT_FILE,
	// MTLS_KEY_FILE, MTLS_CA_FILE) are all set: the gRPC port then serves and
	// dials over mutual TLS. With none set the connector stays plaintext.
	MTLSEnabled bool
	MTLSFiles   mtls.Files
	// HealthPort is the plain, health-only gRPC port the kubelet probe uses
	// when mTLS is on, because it cannot present a client certificate. It is
	// read from HEALTH_PORT like the other services, with MTLS_HEALTH_PORT as
	// a fallback alias for one release.
	HealthPort string
}

func Load() (Config, error) {
	c := Config{
		GRPCPort:     getOr("GRPC_PORT", "9090"),
		OTLPEndpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		HealthPort:   getOr("HEALTH_PORT", getOr("MTLS_HEALTH_PORT", "9091")),
	}
	if err := c.loadMTLS(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// loadMTLS turns mTLS on only when all three files are named. Naming some of
// them is a mistake that would otherwise leave a service plaintext without
// anyone noticing, so it stops the start.
func (c *Config) loadMTLS() error {
	set := 0
	for _, k := range []string{mtls.EnvCertFile, mtls.EnvKeyFile, mtls.EnvCAFile} {
		if os.Getenv(k) != "" {
			set++
		}
	}
	if set == 0 {
		return nil
	}
	files, err := mtls.FilesFromEnv()
	if err != nil {
		return err
	}
	if c.HealthPort == c.GRPCPort {
		return fmt.Errorf("HEALTH_PORT %q is the same as GRPC_PORT; the health port must be plaintext and separate", c.HealthPort)
	}
	c.MTLSEnabled = true
	c.MTLSFiles = files
	return nil
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
