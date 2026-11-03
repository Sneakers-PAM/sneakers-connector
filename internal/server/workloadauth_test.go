// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestInboundAuthIsOffWhenNothingIsSet(t *testing.T) {
	_, mode, err := WorkloadConfigFromEnv(envOf(nil))
	if err != nil || mode != InboundOff {
		t.Fatalf("mode %v, err %v; want InboundOff, nil", mode, err)
	}
}

func TestInboundAuthCanBeDisabledForLocalDevelopment(t *testing.T) {
	_, mode, err := WorkloadConfigFromEnv(envOf(map[string]string{"WORKLOAD_AUTH": "disabled"}))
	if err != nil || mode != InboundDisabled {
		t.Fatalf("mode %v, err %v; want InboundDisabled, nil", mode, err)
	}
}

func TestInboundAuthVerifiesWithTheSneakersDefaults(t *testing.T) {
	cfg, mode, err := WorkloadConfigFromEnv(envOf(map[string]string{
		"WORKLOAD_OIDC_ISSUER":             "https://kubernetes.default.svc.cluster.local",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway",
		"WORKLOAD_SERVICEACCOUNT_PREFIX":   "ignored-",
	}))
	if err != nil || mode != InboundVerified {
		t.Fatalf("mode %v, err %v; want InboundVerified, nil", mode, err)
	}
	if cfg.Audience != WorkloadAudience {
		t.Errorf("audience %q, want %q", cfg.Audience, WorkloadAudience)
	}
	if cfg.ServiceAccountPrefix != WorkloadServiceAccountPrefix {
		t.Errorf("prefix %q, want %q", cfg.ServiceAccountPrefix, WorkloadServiceAccountPrefix)
	}
}

func TestInboundAuthRefusesABadMode(t *testing.T) {
	if _, _, err := WorkloadConfigFromEnv(envOf(map[string]string{"WORKLOAD_AUTH": "off"})); err == nil {
		t.Fatal("WORKLOAD_AUTH=off accepted")
	}
}

func TestInboundAuthRefusesAnIssuerWithAuthDisabled(t *testing.T) {
	_, _, err := WorkloadConfigFromEnv(envOf(map[string]string{
		"WORKLOAD_OIDC_ISSUER":             "https://kubernetes.default.svc.cluster.local",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "sneakers/sneakers-gateway",
		"WORKLOAD_AUTH":                    "disabled",
	}))
	if err == nil {
		t.Fatal("an issuer with WORKLOAD_AUTH=disabled accepted")
	}
}

type readyFunc func() error

func (f readyFunc) Ready() error { return f() }

func TestWorkloadIdentityIsARequiredDependency(t *testing.T) {
	notLoaded := errors.New("key set not loaded")
	dep := WorkloadIdentity(readyFunc(func() error { return notLoaded }))
	if !dep.Required || dep.Name != "workload-identity" {
		t.Fatalf("dependency %+v", dep)
	}
	if err := dep.Check(context.Background()); !errors.Is(err, notLoaded) {
		t.Fatalf("check: %v", err)
	}
}
