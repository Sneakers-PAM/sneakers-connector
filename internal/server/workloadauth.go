// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"strings"

	"github.com/Bugs5382/go-buildinfo/health"
	workloadauth "github.com/Bugs5382/go-workload-identity"
)

// The token audience and the service-account prefix every Sneakers service
// uses. go-workload-identity has no defaults for either, so they are set here.
const (
	// WorkloadAudience is the audience required when WORKLOAD_AUDIENCE is unset.
	WorkloadAudience = "sneakers"
	// WorkloadServiceAccountPrefix is stripped from a service account to give
	// the caller name: "sneakers-gateway" is the caller "gateway".
	WorkloadServiceAccountPrefix = "sneakers-"
)

// InboundMode is how the connector checks the callers of its own API (the
// TLS scan). The health services never need a token.
type InboundMode int

const (
	// InboundOff means no issuer is set: the connector serves only its health
	// services, and the scan API isn't registered at all.
	InboundOff InboundMode = iota
	// InboundDisabled means WORKLOAD_AUTH=disabled: the scan API trusts every
	// caller. Local development only.
	InboundDisabled
	// InboundVerified means every call to the scan API must carry a verified
	// workload token from an allowed caller.
	InboundVerified
)

func (m InboundMode) String() string {
	switch m {
	case InboundDisabled:
		return "disabled"
	case InboundVerified:
		return "verified"
	default:
		return "off"
	}
}

// WorkloadConfigFromEnv reads the WORKLOAD_* variables for the connector's
// own API. Unlike a service whose whole API is behind them, a connector with
// no issuer still starts, as it did before it had an API: it just serves no
// scan (InboundOff). WORKLOAD_AUDIENCE defaults to WorkloadAudience and the
// caller name always drops WorkloadServiceAccountPrefix;
// WORKLOAD_SERVICEACCOUNT_PREFIX is not read.
func WorkloadConfigFromEnv(getenv func(string) string) (workloadauth.Config, InboundMode, error) {
	cfg, enabled, err := workloadauth.ServerConfigFromEnv(withWorkloadAudience(getenv))
	switch {
	case errors.Is(err, workloadauth.ErrNotConfigured):
		return workloadauth.Config{}, InboundOff, nil
	case err != nil:
		return workloadauth.Config{}, InboundOff, err
	case !enabled:
		return workloadauth.Config{}, InboundDisabled, nil
	}
	cfg.ServiceAccountPrefix = WorkloadServiceAccountPrefix
	return cfg, InboundVerified, nil
}

func withWorkloadAudience(getenv func(string) string) func(string) string {
	return func(k string) string {
		switch k {
		case workloadauth.EnvAudience:
			if v := getenv(k); strings.TrimSpace(v) != "" {
				return v
			}
			return WorkloadAudience
		case workloadauth.EnvServiceAccountPrefix:
			return ""
		}
		return getenv(k)
	}
}

// ReadinessVerifier reports whether a caller verifier's key set has loaded,
// the contract go-workload-identity's Verifier.Ready gives.
type ReadinessVerifier interface {
	Ready() error
}

// WorkloadIdentity is the required dependency over a caller verifier: no
// caller can be checked before its key set has loaded, so readiness answers
// NOT_SERVING until then. Build it only in InboundVerified mode.
func WorkloadIdentity(v ReadinessVerifier) health.Dependency {
	return health.Dependency{Name: "workload-identity", Required: true, Check: func(context.Context) error {
		return v.Ready()
	}}
}
