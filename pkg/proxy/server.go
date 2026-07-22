// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kdubbo/dxplane/pkg/policy"
	"github.com/kdubbo/dxplane/pkg/security"
	"github.com/kdubbo/dxplane/pkg/telemetry"
)

type Server struct {
	config       Config
	logger       *slog.Logger
	metrics      *telemetry.Metrics
	policy       *policy.Source
	certificates *security.CertificateSource
	ready        atomic.Bool

	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	connectionsWG sync.WaitGroup
}

func NewServer(config Config, logger *slog.Logger) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	metrics := telemetry.NewMetrics()
	fallback, _ := policy.ParseMode(config.DefaultMode)
	override, hasOverride, _ := policy.ParseOptionalMode(config.ModeOverride)
	policySource := policy.NewSource(config.RuntimeConfigPath, config.PolicyPort, fallback, logger, metrics)
	if hasOverride {
		policySource = policy.NewSource("", config.PolicyPort, override, logger, metrics)
	} else if err := policySource.Reload(); err != nil && !policy.IsNotExist(err) {
		logger.Warn("starting with fail-safe mTLS mode until runtime policy becomes valid", "mode", fallback)
	}

	var certificates *security.CertificateSource
	if !hasOverride || override != policy.ModeDisable {
		certificates = security.NewCertificateSource(config.BootstrapPath, logger, metrics)
		if err := certificates.Reload(); err != nil {
			return nil, fmt.Errorf("load initial certificates: %w", err)
		}
	}

	return &Server{
		config:       config,
		logger:       logger,
		metrics:      metrics,
		policy:       policySource,
		certificates: certificates,
		connections:  make(map[net.Conn]struct{}),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.config.ListenAddress, err)
	}

	var adminListener net.Listener
	if s.config.AdminAddress != "" {
		adminListener, err = net.Listen("tcp", s.config.AdminAddress)
		if err != nil {
			_ = listener.Close()
			return fmt.Errorf("listen on admin address %s: %w", s.config.AdminAddress, err)
		}
	}

	return s.serve(ctx, listener, adminListener)
}

func (s *Server) serve(ctx context.Context, listener, adminListener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if s.certificates != nil {
		go s.certificates.Run(ctx, s.config.ConfigRefreshInterval)
	}
	go s.policy.Run(ctx, s.config.ConfigRefreshInterval)

	errCh := make(chan error, 2)
	if adminListener != nil {
		go func() {
			errCh <- s.serveAdmin(ctx, adminListener)
		}()
	}

	s.ready.Store(true)
	s.logger.Info("dxplane inbound listener ready", "address", listener.Addr().String(), "upstream", s.config.UpstreamAddress)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		errCh <- s.accept(ctx, listener)
	}()

	err := <-errCh
	wasCanceled := ctx.Err() != nil
	cancel()
	s.ready.Store(false)
	_ = listener.Close()
	if adminListener != nil {
		_ = adminListener.Close()
	}
	s.closeConnections()
	s.connectionsWG.Wait()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) && !wasCanceled {
		return err
	}
	return nil
}

func (s *Server) accept(ctx context.Context, listener net.Listener) error {
	var slots chan struct{}
	if s.config.MaxConnections > 0 {
		slots = make(chan struct{}, s.config.MaxConnections)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept inbound connection: %w", err)
		}
		if slots != nil {
			select {
			case slots <- struct{}{}:
			default:
				s.metrics.ConnectionRejected()
				_ = connection.Close()
				continue
			}
		}

		s.trackConnection(connection)
		s.connectionsWG.Add(1)
		s.metrics.ConnectionOpened()
		go func() {
			defer s.connectionsWG.Done()
			defer s.untrackConnection(connection)
			defer s.metrics.ConnectionClosed()
			if slots != nil {
				defer func() { <-slots }()
			}
			if err := s.handleConnection(ctx, connection); err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) {
				s.metrics.ConnectionFailed()
				s.logger.Warn("inbound connection failed", "remote", connection.RemoteAddr().String(), "error", err)
			}
		}()
	}
}

func (s *Server) handleConnection(ctx context.Context, downstream net.Conn) error {
	defer func() { _ = downstream.Close() }()
	if err := downstream.SetDeadline(time.Now().Add(s.config.HandshakeTimeout)); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	reader := bufio.NewReader(downstream)
	first, err := reader.Peek(1)
	if err != nil {
		return err
	}
	buffered := &bufferedConn{Conn: downstream, reader: reader}
	mode := s.policy.Mode()
	if isTLSClientHello(first[0]) {
		if mode == policy.ModeDisable {
			return fmt.Errorf("TLS connection rejected in DISABLE mode")
		}
		if s.certificates == nil || s.certificates.Current() == nil {
			return fmt.Errorf("TLS certificate configuration is unavailable")
		}
		tlsConnection := tls.Server(buffered, s.certificates.Current())
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("mTLS handshake: %w", err)
		}
		downstream = tlsConnection
		s.metrics.TLSConnection()
	} else {
		if mode == policy.ModeStrict {
			return fmt.Errorf("plaintext connection rejected in STRICT mode")
		}
		downstream = buffered
		s.metrics.PlaintextConnection()
	}
	if err := downstream.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear handshake deadline: %w", err)
	}

	dialer := net.Dialer{Timeout: s.config.ConnectTimeout, KeepAlive: 30 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", s.config.UpstreamAddress)
	if err != nil {
		return fmt.Errorf("connect local upstream %s: %w", s.config.UpstreamAddress, err)
	}
	defer func() { _ = upstream.Close() }()
	toUpstream, toDownstream, copyErr := copyBothDirections(downstream, upstream)
	s.metrics.AddBytes(uint64(toUpstream), uint64(toDownstream))
	if copyErr != nil {
		return fmt.Errorf("proxy connection: %w", copyErr)
	}
	return nil
}

func (s *Server) serveAdmin(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler:           s.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve admin API: %w", err)
	}
	return nil
}

func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		ready := s.ready.Load() && s.policy.Loaded() && (s.certificates == nil || s.certificates.Loaded())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := s.metrics.WritePrometheus(w); err != nil {
			s.logger.Warn("write metrics response", "error", err)
		}
	})
	return mux
}

func (s *Server) trackConnection(connection net.Conn) {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	s.connections[connection] = struct{}{}
}

func (s *Server) untrackConnection(connection net.Conn) {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	delete(s.connections, connection)
}

func (s *Server) closeConnections() {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	for connection := range s.connections {
		_ = connection.Close()
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}

func isTLSClientHello(first byte) bool {
	return first == 0x16
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

func copyBothDirections(downstream, upstream net.Conn) (toUpstream, toDownstream int64, copyErr error) {
	results := make(chan copyResult, 2)
	go func() {
		copied, err := io.Copy(downstream, upstream)
		closeWrite(downstream)
		results <- copyResult{direction: "upstream-to-downstream", bytes: copied, err: err}
	}()
	go func() {
		copied, err := io.Copy(upstream, downstream)
		closeWrite(upstream)
		results <- copyResult{direction: "downstream-to-upstream", bytes: copied, err: err}
	}()
	for range 2 {
		result := <-results
		switch result.direction {
		case "upstream-to-downstream":
			toDownstream = result.bytes
		case "downstream-to-upstream":
			toUpstream = result.bytes
		}
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			copyErr = errors.Join(copyErr, fmt.Errorf("%s: %w", result.direction, result.err))
		}
	}
	return toUpstream, toDownstream, copyErr
}

func closeWrite(connection net.Conn) {
	if closer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}
