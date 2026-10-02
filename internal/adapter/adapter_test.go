// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"testing"
)

func TestResultString(t *testing.T) {
	cases := map[Result]string{
		Valid:       "valid",
		Invalid:     "invalid",
		Unreachable: "unreachable",
	}
	for result, want := range cases {
		if got := result.String(); got != want {
			t.Fatalf("Result(%d).String() = %q, want %q", result, got, want)
		}
	}
}

func TestResultStringUnknown(t *testing.T) {
	if got := Result(99).String(); got != "unknown" {
		t.Fatalf("Result(99).String() = %q, want %q", got, "unknown")
	}
}

type fakeAdapter struct{}

func (fakeAdapter) Validate(_ context.Context, _ Conn, _ Cred) (Result, string) {
	return Valid, "fake ok"
}

func (fakeAdapter) Rotate(_ context.Context, _ Conn, _ Cred, _ string) (Result, string) {
	return Valid, "fake ok"
}

func TestRegisterGetRoundTrip(t *testing.T) {
	const protocol = "fake-protocol-for-test"
	a := fakeAdapter{}

	Register(protocol, a)

	got, ok := Get(protocol)
	if !ok {
		t.Fatalf("Get(%q) ok = false, want true", protocol)
	}

	result, detail := got.Validate(context.Background(), Conn{}, Cred{})
	if result != Valid || detail != "fake ok" {
		t.Fatalf("Validate() = (%v, %q), want (%v, %q)", result, detail, Valid, "fake ok")
	}
}

func TestGetUnknownProtocol(t *testing.T) {
	if _, ok := Get("does-not-exist"); ok {
		t.Fatalf("Get(%q) ok = true, want false", "does-not-exist")
	}
}

func TestRegistryContainsRegistered(t *testing.T) {
	const protocol = "fake-protocol-for-registry-test"
	Register(protocol, fakeAdapter{})

	reg := Registry()
	if _, ok := reg[protocol]; !ok {
		t.Fatalf("Registry() missing protocol %q", protocol)
	}
}

func TestCredCarriesKeyMaterial(t *testing.T) {
	c := Cred{Username: "svc", PrivateKey: "PEM", Passphrase: "pp"}
	if c.PrivateKey != "PEM" || c.Passphrase != "pp" {
		t.Fatalf("Cred key fields not set: %+v", c)
	}
}
