// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"net"
	"testing"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	commonv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/common/v1"
	connectorv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/connector/v1"
)

// tokenCallers maps a test token to the caller it verifies as.
type tokenCallers map[string]string

func (m tokenCallers) Verify(token string) (workloadauth.Caller, error) {
	name, ok := m[token]
	if !ok {
		return workloadauth.Caller{}, workloadauth.ErrRejected
	}
	return workloadauth.Caller{Name: name, ServiceAccount: "sneakers/sneakers-" + name}, nil
}

// authedConnector serves the health and scan services behind the caller
// policy on loopback and returns clients for both.
func authedConnector(t *testing.T) (commonv1.HealthServiceClient, connectorv1.ConnectorServiceClient) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(AuthServerOptions(tokenCallers{"gw": CallerGateway, "mcp": "mcp"}, log.Nop())...)
	Register(gs)
	RegisterTLSScan(gs, NewTLSScanServer(log.Nop()))
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	cc, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return commonv1.NewHealthServiceClient(cc), connectorv1.NewConnectorServiceClient(cc)
}

func withToken(tok string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+tok)
}

func TestOnlyTheGatewayMayScan(t *testing.T) {
	_, scan := authedConnector(t)
	port, _ := serveSelfSigned(t)

	if _, err := scan.ScanTLSCertificate(context.Background(), scanRequest(port)); status.Code(err) != codes.Unauthenticated {
		t.Errorf("no token: code %v, want Unauthenticated", status.Code(err))
	}
	if _, err := scan.ScanTLSCertificate(withToken("forged"), scanRequest(port)); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad token: code %v, want Unauthenticated", status.Code(err))
	}
	if _, err := scan.ScanTLSCertificate(withToken("mcp"), scanRequest(port)); status.Code(err) != codes.PermissionDenied {
		t.Errorf("mcp: code %v, want PermissionDenied", status.Code(err))
	}
	if _, err := scan.ScanTLSCertificate(withToken("gw"), scanRequest(port)); err != nil {
		t.Errorf("gateway: %v", err)
	}
}

func TestTheHealthServiceNeedsNoToken(t *testing.T) {
	health, _ := authedConnector(t)
	resp, err := health.Check(context.Background(), &commonv1.CheckRequest{})
	if err != nil || resp.GetStatus() != "SERVING" {
		t.Fatalf("health check: %v, %v", resp, err)
	}
}

func TestAGatewayTokenStillCannotScanForAToken(t *testing.T) {
	_, scan := authedConnector(t)
	req := scanRequest(636)
	req.Actor.PrincipalKind = connectorv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN
	_, err := scan.ScanTLSCertificate(withToken("gw"), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code %v, want PermissionDenied", status.Code(err))
	}
}
