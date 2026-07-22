// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"fmt"
	"io"
	"sync/atomic"
)

type Metrics struct {
	connectionsOpened       atomic.Uint64
	connectionsClosed       atomic.Uint64
	connectionsActive       atomic.Int64
	connectionFailures      atomic.Uint64
	connectionRejections    atomic.Uint64
	tlsConnections          atomic.Uint64
	plaintextConnections    atomic.Uint64
	bytesToUpstream         atomic.Uint64
	bytesToDownstream       atomic.Uint64
	configReloadErrors      atomic.Uint64
	certificateReloads      atomic.Uint64
	certificateReloadErrors atomic.Uint64
}

type Snapshot struct {
	ConnectionsOpened       uint64
	ConnectionsClosed       uint64
	ConnectionsActive       int64
	ConnectionFailures      uint64
	ConnectionRejections    uint64
	TLSConnections          uint64
	PlaintextConnections    uint64
	BytesToUpstream         uint64
	BytesToDownstream       uint64
	ConfigReloadErrors      uint64
	CertificateReloads      uint64
	CertificateReloadErrors uint64
}

func NewMetrics() *Metrics {
	return &Metrics{}
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

func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		ConnectionsOpened:       m.connectionsOpened.Load(),
		ConnectionsClosed:       m.connectionsClosed.Load(),
		ConnectionsActive:       m.connectionsActive.Load(),
		ConnectionFailures:      m.connectionFailures.Load(),
		ConnectionRejections:    m.connectionRejections.Load(),
		TLSConnections:          m.tlsConnections.Load(),
		PlaintextConnections:    m.plaintextConnections.Load(),
		BytesToUpstream:         m.bytesToUpstream.Load(),
		BytesToDownstream:       m.bytesToDownstream.Load(),
		ConfigReloadErrors:      m.configReloadErrors.Load(),
		CertificateReloads:      m.certificateReloads.Load(),
		CertificateReloadErrors: m.certificateReloadErrors.Load(),
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
		{"dxplane_connections_opened_total", "Total accepted inbound connections.", "counter", snapshot.ConnectionsOpened},
		{"dxplane_connections_closed_total", "Total completed inbound connections.", "counter", snapshot.ConnectionsClosed},
		{"dxplane_connections_active", "Current active inbound connections.", "gauge", snapshot.ConnectionsActive},
		{"dxplane_connection_failures_total", "Total inbound connection processing failures.", "counter", snapshot.ConnectionFailures},
		{"dxplane_connection_rejections_total", "Total connections rejected by the concurrency limit.", "counter", snapshot.ConnectionRejections},
		{"dxplane_tls_connections_total", "Total accepted TLS connections.", "counter", snapshot.TLSConnections},
		{"dxplane_plaintext_connections_total", "Total accepted plaintext connections.", "counter", snapshot.PlaintextConnections},
		{"dxplane_bytes_to_upstream_total", "Bytes proxied from the caller to the local application.", "counter", snapshot.BytesToUpstream},
		{"dxplane_bytes_to_downstream_total", "Bytes proxied from the local application to the caller.", "counter", snapshot.BytesToDownstream},
		{"dxplane_runtime_config_reload_errors_total", "Total runtime policy reload failures.", "counter", snapshot.ConfigReloadErrors},
		{"dxplane_certificate_reloads_total", "Total successful certificate changes loaded.", "counter", snapshot.CertificateReloads},
		{"dxplane_certificate_reload_errors_total", "Total certificate reload failures.", "counter", snapshot.CertificateReloadErrors},
	}
	for _, metric := range values {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", metric.name, metric.help, metric.name, metric.typ, metric.name, metric.value); err != nil {
			return err
		}
	}
	return nil
}
