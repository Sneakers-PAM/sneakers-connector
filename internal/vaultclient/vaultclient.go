// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package vaultclient dials the vault service's gRPC endpoint on behalf of
// the connector worker (claim/reveal/report calls for heartbeat validation).
package vaultclient

import (
	"os"

	"github.com/Sneakers-PAM/sneakers-connector/internal/server"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// defaultAddr is the vault's address in a local development setup.
const defaultAddr = "localhost:9091"

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
// handler so outbound calls are traced.
func Dial() (*Client, error) {
	addr := env("VAULT_ADDR", defaultAddr)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), server.ClientStatsHandler())
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, VaultServiceClient: vaultv1.NewVaultServiceClient(conn)}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error { return c.conn.Close() }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
