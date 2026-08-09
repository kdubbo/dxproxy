// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kdubbo/dxproxy/pkg/telemetry"
	xdsresolver "github.com/kdubbo/xds-api/grpc/resolver"
)

type CertificateSource struct {
	bootstrapPath string
	logger        *slog.Logger
	metrics       *telemetry.Metrics

	current atomic.Pointer[tls.Config]
	mu      sync.Mutex
	digest  [sha256.Size]byte
	lastErr string
}

func NewCertificateSource(bootstrapPath string, logger *slog.Logger, metrics *telemetry.Metrics) *CertificateSource {
	return &CertificateSource{bootstrapPath: bootstrapPath, logger: logger, metrics: metrics}
}

func (s *CertificateSource) Current() *tls.Config {
	cfg := s.current.Load()
	if cfg == nil {
		return nil
	}
	return cfg.Clone()
}

func (s *CertificateSource) Loaded() bool {
	return s.current.Load() != nil
}

func (s *CertificateSource) Reload() error {
	bootstrap, err := xdsresolver.ParseBootstrap(s.bootstrapPath)
	if err != nil {
		return s.recordError(err)
	}
	provider, ok := bootstrap.CertProviders["default"]
	if !ok {
		return s.recordError(fmt.Errorf("certificate_providers[default] not found in %s", s.bootstrapPath))
	}
	if provider.CertificateFile == "" || provider.PrivateKeyFile == "" || provider.CACertificateFile == "" {
		return s.recordError(fmt.Errorf("certificate provider default requires certificate_file, private_key_file, and ca_certificate_file"))
	}

	certPEM, err := os.ReadFile(provider.CertificateFile)
	if err != nil {
		return s.recordError(fmt.Errorf("read certificate file %s: %w", provider.CertificateFile, err))
	}
	keyPEM, err := os.ReadFile(provider.PrivateKeyFile)
	if err != nil {
		return s.recordError(fmt.Errorf("read private key file %s: %w", provider.PrivateKeyFile, err))
	}
	rootPEM, err := os.ReadFile(provider.CACertificateFile)
	if err != nil {
		return s.recordError(fmt.Errorf("read CA certificate file %s: %w", provider.CACertificateFile, err))
	}
	digest := sha256.Sum256(append(append(append([]byte{}, certPEM...), keyPEM...), rootPEM...))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.Load() != nil && digest == s.digest {
		s.recordRecoveryLocked()
		return nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return s.recordErrorLocked(fmt.Errorf("load certificate/key: %w", err))
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(rootPEM) {
		return s.recordErrorLocked(fmt.Errorf("parse CA certificate %s: no certificates found", provider.CACertificateFile))
	}
	s.current.Store(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	s.digest = digest
	s.metrics.CertificateReloaded()
	s.recordRecoveryLocked()
	s.logger.Info("inbound certificates loaded", "certificate", provider.CertificateFile, "ca", provider.CACertificateFile)
	return nil
}

func (s *CertificateSource) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Reload()
		}
	}
}

func (s *CertificateSource) recordError(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordErrorLocked(err)
}

func (s *CertificateSource) recordErrorLocked(err error) error {
	s.metrics.CertificateReloadFailed()
	if message := err.Error(); message != s.lastErr {
		s.logger.Error("certificate reload failed; retaining last valid certificate", "error", err)
		s.lastErr = message
	}
	return err
}

func (s *CertificateSource) recordRecoveryLocked() {
	if s.lastErr != "" {
		s.logger.Info("certificate reload recovered")
		s.lastErr = ""
	}
}
