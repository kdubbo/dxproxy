// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kdubbo/dxproxy/pkg/policy"
)

// startDrainServer runs a plaintext server against a TCP echo upstream and
// returns the server, its address, and a cancel that starts the drain.
func startDrainServer(t *testing.T, config Config) (*Server, string, context.CancelFunc, <-chan error) {
	t.Helper()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		for {
			connection, acceptErr := upstream.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = connection.Close() }()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.ListenAddress = listener.Addr().String()
	config.UpstreamAddress = upstream.Addr().String()
	config.AdminAddress = ""
	config.ModeOverride = string(policy.ModeDisable)
	config.DefaultMode = string(policy.ModeStrict)
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = time.Second
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = time.Second
	}
	if config.ConfigRefreshInterval == 0 {
		config.ConfigRefreshInterval = time.Second
	}

	server, err := NewServer(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		_ = listener.Close()
		t.Fatalf("NewServer() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.serve(ctx, listener, nil) }()

	deadline := time.Now().Add(time.Second)
	for !server.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.ready.Load() {
		cancel()
		t.Fatal("server did not become ready")
	}
	return server, listener.Addr().String(), cancel, errCh
}

func TestDrainWithdrawsEndpointBeforeClosingListener(t *testing.T) {
	server, address, cancel, errCh := startDrainServer(t, Config{
		TerminationDrainDelay:    300 * time.Millisecond,
		TerminationDrainDuration: time.Second,
	})

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("readiness before drain = %d, want %d", response.Code, http.StatusOK)
	}

	cancel()

	// During the withdrawal window readiness must already fail, while the
	// listener still accepts: that is what lets a caller with stale EDS through.
	waitFor(t, time.Second, func() bool { return server.terminating.Load() })
	response = httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness during withdrawal = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("connection during withdrawal window rejected: %v", err)
	}
	if err := echo(connection, "late"); err != nil {
		t.Fatalf("late connection failed: %v", err)
	}
	_ = connection.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("serve() error = %v", err)
	}
	if _, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		t.Fatal("listener still accepting after drain")
	}
}

func TestDrainWaitsForInFlightConnection(t *testing.T) {
	server, address, cancel, errCh := startDrainServer(t, Config{
		TerminationDrainDuration: 3 * time.Second,
	})

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := echo(connection, "first"); err != nil {
		t.Fatalf("initial echo failed: %v", err)
	}
	waitFor(t, time.Second, func() bool { return server.activeConnections() == 1 })

	cancel()

	// The connection is still open, so serve() must not return yet.
	select {
	case err := <-errCh:
		t.Fatalf("serve() returned while a connection was in flight: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// It also has to keep working: draining is not the same as cutting.
	if err := echo(connection, "during-drain"); err != nil {
		t.Fatalf("in-flight connection broke during drain: %v", err)
	}
	_ = connection.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not return after the connection closed")
	}
	if forced := server.metrics.Snapshot().ConnectionsForceClosed; forced != 0 {
		t.Fatalf("force-closed connections = %d, want 0", forced)
	}
}

func TestDrainForceClosesWhenBudgetExpires(t *testing.T) {
	server, address, cancel, errCh := startDrainServer(t, Config{
		TerminationDrainDuration: 200 * time.Millisecond,
	})

	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := echo(connection, "stuck"); err != nil {
		t.Fatalf("initial echo failed: %v", err)
	}
	waitFor(t, time.Second, func() bool { return server.activeConnections() == 1 })

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve() did not return after the drain budget expired")
	}

	snapshot := server.metrics.Snapshot()
	if snapshot.ConnectionsForceClosed != 1 {
		t.Fatalf("force-closed connections = %d, want 1", snapshot.ConnectionsForceClosed)
	}
	if !snapshot.Terminating {
		t.Fatal("terminating metric not set after drain")
	}
	if snapshot.DrainDuration <= 0 {
		t.Fatalf("drain duration = %v, want a positive value", snapshot.DrainDuration)
	}
}

func echo(connection net.Conn, payload string) error {
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(connection, payload); err != nil {
		return err
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		return err
	}
	if string(buffer) != payload {
		return io.ErrUnexpectedEOF
	}
	return connection.SetDeadline(time.Time{})
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
