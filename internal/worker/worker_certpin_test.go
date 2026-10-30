// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

func TestCertificateMismatchFailsARotation(t *testing.T) {
	if got := toRotationPhase(adapter.CertificateMismatch); got != vaultv1.RotationPhase_ROTATION_PHASE_FAILED {
		t.Errorf("toRotationPhase(CertificateMismatch) = %v, want FAILED", got)
	}
}
