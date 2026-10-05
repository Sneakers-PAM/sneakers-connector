// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package vaultclient dials the vault service's gRPC endpoint on behalf of
// the connector worker (claim/reveal/report calls for heartbeat validation).
package vaultclient

import (
	"context"
	"fmt"
	"os"

	vaultv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/buildinfo"
	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
	"github.com/Sneakers-PAM/sneakers-connector/internal/tokensource"
	"github.com/Sneakers-PAM/sneakers-connector/internal/workloadauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// defaultAddr is the vault's address in a local development setup.
const defaultAddr = "localhost:9091"

const (
	// EnvWorkloadTokenFile names the projected workload token sent to the
	// vault on every call.
	EnvWorkloadTokenFile = workloadauth.EnvTokenFile
	// EnvConnectorTokenFile is the older name for the same file, read when
	// EnvWorkloadTokenFile is unset.
	EnvConnectorTokenFile = tokensource.EnvTokenFile
)

// Client wraps the dialled gRPC connection alongside the generated vault
// client so callers get one value to hold and Close, while still satisfying
// vaultv1.VaultServiceClient directly (via the embedded interface) for
// passing into worker.Run.
type Client struct {
	conn *grpc.ClientConn
	vaultv1.VaultServiceClient
}

// Dial connects to VAULT_ADDR (env, default localhost:9091) with insecure
// transport credentials (the connection carries no TLS of its own; run it
// where the network or a mesh protects it) plus the OTel client stats
// handler so outbound calls are traced. Every call carries the workload
// token from WORKLOAD_TOKEN_FILE (or CONNECTOR_TOKEN_FILE) as
// "authorization: Bearer <token>", re-read on each call. With neither set no
// token is sent, which only a vault with authentication off accepts. Every
// call also carries the connector's build as MDVersion and MDCommit, which the
// vault records for diagnostics.
func Dial() (*Client, error) { return dial(os.Getenv) }

func dial(getenv func(string) string) (*Client, error) {
	addr := getenv("VAULT_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	version, commit := buildinfo.Info()
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler(),
		grpc.WithChainUnaryInterceptor(buildUnaryInterceptor(version, commit)),
		grpc.WithChainStreamInterceptor(buildStreamInterceptor(version, commit)),
	}
	tokenOpt, ok, err := workloadauth.DialOptionFromEnv(tokenFileAlias(getenv))
	if err != nil {
		return nil, fmt.Errorf("vault workload token: %w", err)
	}
	if ok {
		opts = append(opts, tokenOpt)
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, VaultServiceClient: vaultv1.NewVaultServiceClient(conn)}, nil
}

// tokenFileAlias answers EnvWorkloadTokenFile with EnvConnectorTokenFile
// when only the older name is set.
func tokenFileAlias(getenv func(string) string) func(string) string {
	return func(k string) string {
		v := getenv(k)
		if k == EnvWorkloadTokenFile && v == "" {
			return getenv(EnvConnectorTokenFile)
		}
		return v
	}
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

// Conn is the connection to the vault, for its health check (readiness).
func (c *Client) Conn() grpc.ClientConnInterface { return c.conn }

// Metadata keys that carry the connector's build on every call to the vault.
const (
	MDVersion = "sneakers-version"
	MDCommit  = "sneakers-commit"
)

func withBuild(ctx context.Context, version, commit string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, MDVersion, version, MDCommit, commit)
}

func buildUnaryInterceptor(version, commit string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(withBuild(ctx, version, commit), method, req, reply, cc, opts...)
	}
}

func buildStreamInterceptor(version, commit string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(withBuild(ctx, version, commit), desc, cc, method, opts...)
	}
}
