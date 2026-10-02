// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// seqSource hands out tokens in order, repeating the last, so a test can
// see the worker ask for a fresh token on every tick.
type seqSource struct {
	mu     sync.Mutex
	tokens []string
	calls  int
}

func (s *seqSource) Token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := min(s.calls, len(s.tokens)-1)
	s.calls++
	return s.tokens[i]
}

// tokenRecordingClient records the identity token on every claim, guarded
// because Run is driven from its own goroutine here.
type tokenRecordingClient struct {
	vaultv1.VaultServiceClient

	mu             sync.Mutex
	heartbeatToks  []string
	rotationToks   []string
	enoughRotation chan struct{}
	want           int
}

func (c *tokenRecordingClient) ClaimDueHeartbeats(_ context.Context, in *vaultv1.ClaimDueHeartbeatsRequest, _ ...grpc.CallOption) (*vaultv1.ClaimDueHeartbeatsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.heartbeatToks = append(c.heartbeatToks, in.GetIdentity().GetToken())
	return &vaultv1.ClaimDueHeartbeatsResponse{}, nil
}

func (c *tokenRecordingClient) ClaimDueRotations(_ context.Context, in *vaultv1.ClaimDueRotationsRequest, _ ...grpc.CallOption) (*vaultv1.ClaimDueRotationsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rotationToks = append(c.rotationToks, in.GetIdentity().GetToken())
	if len(c.rotationToks) == c.want {
		close(c.enoughRotation)
	}
	return &vaultv1.ClaimDueRotationsResponse{}, nil
}

func TestRunWithSourceReadsTokenEveryTick(t *testing.T) {
	src := &seqSource{tokens: []string{"tok-a", "tok-b"}}
	vc := &tokenRecordingClient{enoughRotation: make(chan struct{}), want: 2}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		RunWithSource(ctx, vc, src, time.Millisecond)
		close(done)
	}()

	select {
	case <-vc.enoughRotation:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not complete two ticks")
	}
	cancel()
	<-done

	vc.mu.Lock()
	defer vc.mu.Unlock()
	if vc.heartbeatToks[0] != "tok-a" || vc.rotationToks[0] != "tok-a" {
		t.Fatalf("first tick tokens = %q/%q, want tok-a", vc.heartbeatToks[0], vc.rotationToks[0])
	}
	if vc.heartbeatToks[1] != "tok-b" || vc.rotationToks[1] != "tok-b" {
		t.Fatalf("second tick tokens = %q/%q, want tok-b", vc.heartbeatToks[1], vc.rotationToks[1])
	}
}
