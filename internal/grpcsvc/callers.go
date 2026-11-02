// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"

	commonv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/common/v1"
	connectorv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/connector/v1"
)

// CallerGateway is the only caller of the connector's own API: the gateway,
// service account sneakers-gateway.
const CallerGateway = "gateway"

// CallerPolicy is the connector's per-method allow-list. Only the gateway may
// scan, passing the signed-in person's actor. Every other caller, the MCP
// server included, is refused.
func CallerPolicy() workloadauth.Policy {
	return workloadauth.Policy{
		connectorv1.ConnectorService_ScanTLSCertificate_FullMethodName: {CallerGateway: workloadauth.OnBehalf},
	}
}

// exemptServices answer without a token, as they did before the connector had
// an API: probes, the gateway's telemetry rollup and server reflection.
var exemptServices = []string{
	"/" + commonv1.HealthService_ServiceDesc.ServiceName + "/",
	"/grpc.reflection.v1.ServerReflection/",
	"/grpc.reflection.v1alpha.ServerReflection/",
}

// AuthServerOptions returns the interceptors that check every call's workload
// token against CallerPolicy. Refusals are logged at warn by the interceptor.
func AuthServerOptions(v workloadauth.TokenVerifier, lg log.Logger) []grpc.ServerOption {
	p := CallerPolicy()
	exempt := workloadauth.WithExempt(exemptServices...)
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(v, p, lg, exempt)),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, p, lg, exempt)),
	}
}
