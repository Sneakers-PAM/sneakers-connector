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
	// MTLSHealthPort is the plain, health-only gRPC port the kubelet probe
	// uses, because it cannot present a client certificate. Required when
	// mTLS is on.
	MTLSHealthPort string
}

func Load() (Config, error) {
	c := Config{
		GRPCPort:       getOr("GRPC_PORT", "9090"),
		OTLPEndpoint:   os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		MTLSHealthPort: os.Getenv("MTLS_HEALTH_PORT"),
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
	if c.MTLSHealthPort == "" {
		return fmt.Errorf("MTLS_HEALTH_PORT is required when mTLS is on: the kubelet probe cannot present a client certificate")
	}
	if c.MTLSHealthPort == c.GRPCPort {
		return fmt.Errorf("MTLS_HEALTH_PORT %q is the same as GRPC_PORT; the health port must be plaintext and separate", c.MTLSHealthPort)
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
