// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"

	"github.com/Sneakers-PAM/sneakers-connector/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HeaderHealth carries a readiness check's dependency report as compact JSON.
const HeaderHealth = "sneakers-health"

// LivenessService is the health service name the liveness probe asks for. It
// answers SERVING whenever the process does and never touches a dependency.
const LivenessService = "liveness"

// healthServer answers the standard gRPC health check. Service "" is
// readiness: NOT_SERVING while a required dependency is down.
type healthServer struct {
	healthpb.UnimplementedHealthServer
	checker *health.Checker
}

func (h *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	switch req.GetService() {
	case LivenessService:
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	case "":
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	r := health.Report{Status: health.StateOK, Dependencies: []health.DepState{}}
	if h.checker != nil {
		r = h.checker.Report(ctx)
	}
	if body, err := json.Marshal(r); err == nil {
		_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(body)))
	}
	st := healthpb.HealthCheckResponse_SERVING
	if r.Status == health.StateDown {
		st = healthpb.HealthCheckResponse_NOT_SERVING
	}
	return &healthpb.HealthCheckResponse{Status: st}, nil
}

func (h *healthServer) Watch(*healthpb.HealthCheckRequest, healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "watch is not supported; poll Check")
}
