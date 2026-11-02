// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	connectorv1 "github.com/Sneakers-PAM/sneakers-connector/gen/go/sneakers/connector/v1"
	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

const (
	// defaultScanPort is LDAPS, the TLS target the connector dials today.
	defaultScanPort = 636
	// scanBurst scans a person may run back to back, refilled one per
	// scanRefill, so the connector can't be driven as a port scanner.
	scanBurst  = 5
	scanRefill = 12 * time.Second
)

// TLSScanServer implements ConnectorService.ScanTLSCertificate.
type TLSScanServer struct {
	connectorv1.UnimplementedConnectorServiceServer
	log     log.Logger
	limit   *scanLimiter
	timeout time.Duration
	scan    func(ctx context.Context, host string, port int, timeout time.Duration) (adapter.TLSScan, error)
}

// NewTLSScanServer returns the scan service, logging through lg.
func NewTLSScanServer(lg log.Logger) *TLSScanServer {
	return &TLSScanServer{
		log:     lg.With(log.F("component", "tls-scan")),
		limit:   newScanLimiter(),
		timeout: adapter.DefaultScanTimeout,
		scan:    adapter.ScanTLSCertificate,
	}
}

// RegisterTLSScan wires the scan service into a gRPC server.
func RegisterTLSScan(gs *grpc.Server, s *TLSScanServer) {
	connectorv1.RegisterConnectorServiceServer(gs, s)
}

// ScanTLSCertificate reads the certificate chain a target sends during the
// TLS handshake. It never sends application data. Each scan is logged at
// info with the leaf's fingerprint; no certificate body is logged.
func (s *TLSScanServer) ScanTLSCertificate(ctx context.Context, req *connectorv1.ScanTLSCertificateRequest) (*connectorv1.ScanTLSCertificateResponse, error) {
	lg := s.log.Ctx(ctx).With(log.F("target_id", req.GetTargetId()), log.F("actor_user_id", req.GetActorUserId()))
	if kind := req.GetActor().GetPrincipalKind(); kind != connectorv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		lg.Warn("tls scan refused: principal kind not allowed", log.F("principal_kind", kind.String()))
		return nil, status.Error(codes.PermissionDenied, "certificate scans are for people in the web app only")
	}
	if req.GetHost() == "" || req.GetTargetId() == "" || req.GetActorUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "host, target_id and actor_user_id are required")
	}
	port := int(req.GetPort())
	if port == 0 {
		port = defaultScanPort
	}
	if port < 1 || port > 65535 {
		return nil, status.Error(codes.InvalidArgument, "port must be between 1 and 65535")
	}
	if !s.limit.allow(req.GetActorUserId()) {
		lg.Warn("tls scan refused: rate limited")
		return nil, status.Error(codes.ResourceExhausted, "too many certificate scans; try again shortly")
	}

	lg = lg.With(log.F("host", req.GetHost()), log.F("port", port))
	lg.Debug("tls scan start")
	start := time.Now()
	scan, err := s.scan(ctx, req.GetHost(), port, s.timeout)
	dur := time.Since(start)
	if err != nil {
		outcome := adapter.ScanHandshakeFailed
		var se *adapter.ScanError
		if errors.As(err, &se) {
			outcome = se.Outcome
		}
		lg.Warn("tls scan failed", log.F("outcome", outcome), log.F("duration", dur.String()), log.F("error", err.Error()))
		if outcome == adapter.ScanUnreachable {
			return nil, status.Error(codes.Unavailable, "target unreachable")
		}
		return nil, status.Error(codes.Unavailable, "no TLS certificate offered")
	}
	lg.Info("tls certificate scanned",
		log.F("address", scan.Address),
		log.F("leaf_fingerprint_sha256", scan.Chain[0].FingerprintSHA256),
		log.F("chain_length", len(scan.Chain)),
		log.F("system_trusted", scan.SystemTrusted),
		log.F("host_name_matches", scan.HostNameMatches),
		log.F("duration", dur.String()))
	return scanResponse(scan), nil
}

func scanResponse(scan adapter.TLSScan) *connectorv1.ScanTLSCertificateResponse {
	resp := &connectorv1.ScanTLSCertificateResponse{
		Address:           scan.Address,
		ServerName:        scan.ServerName,
		TlsVersion:        scan.TLSVersion,
		SystemTrusted:     scan.SystemTrusted,
		SystemTrustDetail: scan.SystemTrustDetail,
		HostNameMatches:   scan.HostNameMatches,
	}
	for _, c := range scan.Chain {
		resp.Chain = append(resp.Chain, &connectorv1.ScannedCertificate{
			Subject:           c.Subject,
			CommonName:        c.CommonName,
			DnsNames:          c.DNSNames,
			IpAddresses:       c.IPAddresses,
			Issuer:            c.Issuer,
			NotBefore:         timestamppb.New(c.NotBefore),
			NotAfter:          timestamppb.New(c.NotAfter),
			FingerprintSha256: c.FingerprintSHA256,
			SerialNumber:      c.SerialNumber,
			IsCa:              c.IsCA,
			SelfSigned:        c.SelfSigned,
			Pinnable:          c.Pinnable,
		})
	}
	return resp
}

// scanLimiter is a token bucket per person.
type scanLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*scanBucket
}

type scanBucket struct {
	tokens float64
	at     time.Time
}

func newScanLimiter() *scanLimiter {
	return &scanLimiter{now: time.Now, buckets: map[string]*scanBucket{}}
}

func (l *scanLimiter) allow(actor string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if now.Sub(b.at) > scanBurst*scanRefill {
			delete(l.buckets, k)
		}
	}
	b, ok := l.buckets[actor]
	if !ok {
		b = &scanBucket{tokens: scanBurst, at: now}
		l.buckets[actor] = b
	}
	b.tokens += float64(now.Sub(b.at)) / float64(scanRefill)
	if b.tokens > scanBurst {
		b.tokens = scanBurst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
