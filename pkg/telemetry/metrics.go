// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	RequestCountEnabled      bool
	RemoveGRPCResponseStatus bool
}

type Metrics struct {
	connectionsOpened       atomic.Uint64
	connectionsClosed       atomic.Uint64
	connectionsActive       atomic.Int64
	connectionFailures      atomic.Uint64
	connectionRejections    atomic.Uint64
	connectionsForceClosed  atomic.Uint64
	faultDelays             atomic.Uint64
	faultAborts             atomic.Uint64
	authorizationDenials    atomic.Uint64
	tlsConnections          atomic.Uint64
	plaintextConnections    atomic.Uint64
	bytesToUpstream         atomic.Uint64
	bytesToDownstream       atomic.Uint64
	configReloadErrors      atomic.Uint64
	certificateReloads      atomic.Uint64
	certificateReloadErrors atomic.Uint64
	terminating             atomic.Bool
	drainNanoseconds        atomic.Int64
	requestCountEnabled     atomic.Bool
	removeResponseStatus    atomic.Bool
	requestsMu              sync.RWMutex
	requestsByStatus        map[string]uint64
}

type Snapshot struct {
	ConnectionsOpened       uint64
	ConnectionsClosed       uint64
	ConnectionsActive       int64
	ConnectionFailures      uint64
	ConnectionRejections    uint64
	ConnectionsForceClosed  uint64
	FaultDelays             uint64
	FaultAborts             uint64
	AuthorizationDenials    uint64
	TLSConnections          uint64
	PlaintextConnections    uint64
	BytesToUpstream         uint64
	BytesToDownstream       uint64
	ConfigReloadErrors      uint64
	CertificateReloads      uint64
	CertificateReloadErrors uint64
	Terminating             bool
	DrainDuration           time.Duration
}

func NewMetrics() *Metrics {
	return &Metrics{requestsByStatus: make(map[string]uint64)}
}

func (m *Metrics) Configure(config Config) {
	m.requestCountEnabled.Store(config.RequestCountEnabled)
	m.removeResponseStatus.Store(config.RemoveGRPCResponseStatus)
}

func (m *Metrics) RequestCompleted(grpcResponseStatus string) {
	if !m.requestCountEnabled.Load() {
		return
	}
	if grpcResponseStatus == "" {
		grpcResponseStatus = "2"
	}
	m.requestsMu.Lock()
	m.requestsByStatus[grpcResponseStatus]++
	m.requestsMu.Unlock()
}

func (m *Metrics) ConnectionOpened() {
	m.connectionsOpened.Add(1)
	m.connectionsActive.Add(1)
}

func (m *Metrics) ConnectionClosed() {
	m.connectionsClosed.Add(1)
	m.connectionsActive.Add(-1)
}

func (m *Metrics) ConnectionFailed() {
	m.connectionFailures.Add(1)
}

func (m *Metrics) ConnectionRejected() {
	m.connectionRejections.Add(1)
}

func (m *Metrics) FaultDelayed() {
	m.faultDelays.Add(1)
}

func (m *Metrics) FaultAborted() {
	m.faultAborts.Add(1)
}

func (m *Metrics) AuthorizationDenied() {
	m.authorizationDenials.Add(1)
}

func (m *Metrics) TLSConnection() {
	m.tlsConnections.Add(1)
}

func (m *Metrics) PlaintextConnection() {
	m.plaintextConnections.Add(1)
}

func (m *Metrics) AddBytes(toUpstream, toDownstream uint64) {
	m.bytesToUpstream.Add(toUpstream)
	m.bytesToDownstream.Add(toDownstream)
}

func (m *Metrics) ConfigReloadFailed() {
	m.configReloadErrors.Add(1)
}

func (m *Metrics) CertificateReloaded() {
	m.certificateReloads.Add(1)
}

func (m *Metrics) CertificateReloadFailed() {
	m.certificateReloadErrors.Add(1)
}

// TerminationStarted marks the pod as draining. Scrapers and the readiness
// endpoint use this to tell "unhealthy" apart from "shutting down on purpose".
func (m *Metrics) TerminationStarted() {
	m.terminating.Store(true)
}

// ConnectionsForceClosed counts connections cut because the drain budget ran
// out. A non-zero value means the budget is too short for the workload.
func (m *Metrics) ConnectionsForceClosed(count uint64) {
	m.connectionsForceClosed.Add(count)
}

func (m *Metrics) TerminationCompleted(elapsed time.Duration) {
	m.drainNanoseconds.Store(elapsed.Nanoseconds())
}

func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		ConnectionsOpened:       m.connectionsOpened.Load(),
		ConnectionsClosed:       m.connectionsClosed.Load(),
		ConnectionsActive:       m.connectionsActive.Load(),
		ConnectionFailures:      m.connectionFailures.Load(),
		ConnectionRejections:    m.connectionRejections.Load(),
		ConnectionsForceClosed:  m.connectionsForceClosed.Load(),
		FaultDelays:             m.faultDelays.Load(),
		FaultAborts:             m.faultAborts.Load(),
		AuthorizationDenials:    m.authorizationDenials.Load(),
		TLSConnections:          m.tlsConnections.Load(),
		PlaintextConnections:    m.plaintextConnections.Load(),
		BytesToUpstream:         m.bytesToUpstream.Load(),
		BytesToDownstream:       m.bytesToDownstream.Load(),
		ConfigReloadErrors:      m.configReloadErrors.Load(),
		CertificateReloads:      m.certificateReloads.Load(),
		CertificateReloadErrors: m.certificateReloadErrors.Load(),
		Terminating:             m.terminating.Load(),
		DrainDuration:           time.Duration(m.drainNanoseconds.Load()),
	}
}

func (m *Metrics) WritePrometheus(w io.Writer) error {
	snapshot := m.Snapshot()
	values := []struct {
		name  string
		help  string
		typ   string
		value any
	}{
		{"dxproxy_connections_opened_total", "Total accepted inbound connections.", "counter", snapshot.ConnectionsOpened},
		{"dxproxy_connections_closed_total", "Total completed inbound connections.", "counter", snapshot.ConnectionsClosed},
		{"dxproxy_connections_active", "Current active inbound connections.", "gauge", snapshot.ConnectionsActive},
		{"dxproxy_connection_failures_total", "Total inbound connection processing failures.", "counter", snapshot.ConnectionFailures},
		{"dxproxy_connection_rejections_total", "Total connections rejected by the concurrency limit.", "counter", snapshot.ConnectionRejections},
		{"dxproxy_connections_force_closed_total", "Total connections closed because the drain budget expired.", "counter", snapshot.ConnectionsForceClosed},
		{"dxproxy_fault_delays_total", "Total inbound connections delayed by fault injection.", "counter", snapshot.FaultDelays},
		{"dxproxy_fault_aborts_total", "Total inbound connections aborted by fault injection.", "counter", snapshot.FaultAborts},
		{"dxproxy_authorization_denials_total", "Total inbound connections denied by authorization policy.", "counter", snapshot.AuthorizationDenials},
		{"dxproxy_tls_connections_total", "Total accepted TLS connections.", "counter", snapshot.TLSConnections},
		{"dxproxy_plaintext_connections_total", "Total accepted plaintext connections.", "counter", snapshot.PlaintextConnections},
		{"dxproxy_bytes_to_upstream_total", "Bytes proxied from the caller to the local application.", "counter", snapshot.BytesToUpstream},
		{"dxproxy_bytes_to_downstream_total", "Bytes proxied from the local application to the caller.", "counter", snapshot.BytesToDownstream},
		{"dxproxy_runtime_config_reload_errors_total", "Total runtime policy reload failures.", "counter", snapshot.ConfigReloadErrors},
		{"dxproxy_certificate_reloads_total", "Total successful certificate changes loaded.", "counter", snapshot.CertificateReloads},
		{"dxproxy_certificate_reload_errors_total", "Total certificate reload failures.", "counter", snapshot.CertificateReloadErrors},
		{"dxproxy_terminating", "Set to 1 once the pod has started draining.", "gauge", boolValue(snapshot.Terminating)},
		{"dxproxy_drain_duration_seconds", "Time the last completed drain took, in seconds.", "gauge", snapshot.DrainDuration.Seconds()},
	}
	for _, metric := range values {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", metric.name, metric.help, metric.name, metric.typ, metric.name, metric.value); err != nil {
			return err
		}
	}
	if m.requestCountEnabled.Load() {
		if err := m.writeRequestCount(w); err != nil {
			return err
		}
	}
	return nil
}

func (m *Metrics) writeRequestCount(w io.Writer) error {
	m.requestsMu.RLock()
	statuses := make([]string, 0, len(m.requestsByStatus))
	var total uint64
	for status, count := range m.requestsByStatus {
		statuses = append(statuses, status)
		total += count
	}
	sort.Strings(statuses)
	m.requestsMu.RUnlock()

	const (
		name = "dubbo_inherent_requests_total"
		help = "Total completed Inherent gRPC requests."
	)
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name); err != nil {
		return err
	}
	if m.removeResponseStatus.Load() {
		_, err := fmt.Fprintf(w, "%s{reporter=\"server\"} %d\n", name, total)
		return err
	}
	for _, status := range statuses {
		m.requestsMu.RLock()
		count := m.requestsByStatus[status]
		m.requestsMu.RUnlock()
		if _, err := fmt.Fprintf(w, "%s{reporter=\"server\",grpc_response_status=%q} %d\n", name, status, count); err != nil {
			return err
		}
	}
	return nil
}

func boolValue(value bool) int {
	if value {
		return 1
	}
	return 0
}
