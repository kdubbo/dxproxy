// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kdubbo/dxproxy/pkg/policy"
	"github.com/kdubbo/dxproxy/pkg/security"
	"github.com/kdubbo/dxproxy/pkg/telemetry"
)

func TestServerStrictMTLSAndProxy(t *testing.T) {
	material := writeCertificateMaterial(t, t.TempDir(), "one")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "upstream-ok\n")
	}))
	defer upstream.Close()

	server, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		BootstrapPath:         material.bootstrap,
		ModeOverride:          string(policy.ModeStrict),
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: 20 * time.Millisecond,
	}, material)
	defer stop()

	plainClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	if _, err := plainClient.Get("http://" + address + "/"); err == nil {
		t.Fatal("plaintext request succeeded in STRICT mode")
	}

	response, err := material.client().Get("https://" + address + "/")
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "upstream-ok\n" {
		t.Fatalf("body = %q, want upstream response", body)
	}
	if got := server.metrics.Snapshot().TLSConnections; got != 1 {
		t.Fatalf("TLS connections = %d, want 1", got)
	}
}

func TestServerPermissiveAcceptsPlaintext(t *testing.T) {
	material := writeCertificateMaterial(t, t.TempDir(), "one")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "plain-ok\n")
	}))
	defer upstream.Close()

	server, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		BootstrapPath:         material.bootstrap,
		ModeOverride:          string(policy.ModePermissive),
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
	}, material)
	defer stop()

	response, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Get("http://" + address + "/")
	if err != nil {
		t.Fatalf("plaintext request failed: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "plain-ok\n" {
		t.Fatalf("body = %q, want upstream response", body)
	}
	if got := server.metrics.Snapshot().PlaintextConnections; got != 1 {
		t.Fatalf("plaintext connections = %d, want 1", got)
	}
}

func TestServerDisableDoesNotRequireBootstrap(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "disabled-ok\n")
	}))
	defer upstream.Close()

	_, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		ModeOverride:          string(policy.ModeDisable),
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
	}, certificateMaterial{})
	defer stop()

	response, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Get("http://" + address + "/")
	if err != nil {
		t.Fatalf("plaintext request failed: %v", err)
	}
	_ = response.Body.Close()
}

func TestServerAppliesInboundFaultBeforeUpstream(t *testing.T) {
	material := writeCertificateMaterial(t, t.TempDir(), "one")
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "unexpected\n")
	}))
	defer upstream.Close()

	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	runtime := `{
		"version":"dubbo.apache.org/inherent-grpc/v1",
		"services":[{
			"host":"local.default.svc",
			"ports":[{
				"port":80,
				"mtlsMode":"PERMISSIVE",
				"fault":{
					"delay":{"fixedDelay":"20ms","percentage":100},
					"abort":{"httpStatus":503,"percentage":100}
				}
			}]
		}]
	}`
	if err := os.WriteFile(runtimePath, []byte(runtime), 0o600); err != nil {
		t.Fatal(err)
	}

	server, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		BootstrapPath:         material.bootstrap,
		RuntimeConfigPath:     runtimePath,
		PolicyPort:            80,
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
	}, material)
	defer stop()

	started := time.Now()
	_, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Get("http://" + address + "/")
	if err == nil {
		t.Fatal("fault-injected request succeeded")
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("fault delay elapsed = %v, want at least 20ms", elapsed)
	}
	if requests.Load() != 0 {
		t.Fatalf("upstream requests = %d, want 0", requests.Load())
	}
	snapshot := server.metrics.Snapshot()
	if snapshot.FaultDelays != 1 || snapshot.FaultAborts != 1 {
		t.Fatalf("fault metrics = delays:%d aborts:%d, want 1/1", snapshot.FaultDelays, snapshot.FaultAborts)
	}
}

func TestServerEnforcesConnectionAuthorizationPolicy(t *testing.T) {
	material := writeCertificateMaterial(t, t.TempDir(), "authz")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("denied connection reached upstream")
	}))
	defer upstream.Close()

	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	runtime := `{
		"version":"dubbo.apache.org/inherent-grpc/v1",
		"services":[{"host":"local.default.svc","ports":[{
			"port":8080,
			"mtlsMode":"PERMISSIVE",
			"authorizationPolicies":[{
				"name":"deny-loopback",
				"action":"DENY",
				"rules":[{"sources":[{"ipBlocks":["127.0.0.0/8"]}]}]
			}]
		}]}]
	}`
	if err := os.WriteFile(runtimePath, []byte(runtime), 0o600); err != nil {
		t.Fatal(err)
	}

	server, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		BootstrapPath:         material.bootstrap,
		RuntimeConfigPath:     runtimePath,
		PolicyPort:            8080,
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
	}, material)
	defer stop()

	_, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Get("http://" + address + "/")
	if err == nil {
		t.Fatal("denied request succeeded")
	}
	if server.metrics.Snapshot().AuthorizationDenials != 1 {
		t.Fatalf("authorization denials = %d, want 1", server.metrics.Snapshot().AuthorizationDenials)
	}
}

func TestServerEnforcesMinimumTLS13(t *testing.T) {
	material := writeCertificateMaterial(t, t.TempDir(), "tls13")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls13-ok\n")
	}))
	defer upstream.Close()

	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	runtime := `{
		"version":"dubbo.apache.org/inherent-grpc/v1",
		"services":[{"host":"local.default.svc","ports":[{
			"port":8443,
			"mtlsMode":"STRICT",
			"minimumTlsVersion":"TLSV1_3"
		}]}]
	}`
	if err := os.WriteFile(runtimePath, []byte(runtime), 0o600); err != nil {
		t.Fatal(err)
	}

	_, address, stop := startTestServer(t, Config{
		UpstreamAddress:       upstream.Listener.Addr().String(),
		BootstrapPath:         material.bootstrap,
		RuntimeConfigPath:     runtimePath,
		PolicyPort:            8443,
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
	}, material)
	defer stop()

	clientTLS12 := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		RootCAs:      material.rootPool,
		ServerName:   "dxproxy.test",
		Certificates: []tls.Certificate{material.clientCert},
	}
	connection, err := tls.Dial("tcp", address, clientTLS12)
	if err == nil {
		_ = connection.Close()
		t.Fatal("TLS 1.2 handshake succeeded with TLSV1_3 minimum")
	}

	response, err := material.client().Get("https://" + address + "/")
	if err != nil {
		t.Fatalf("TLS 1.3 request failed: %v", err)
	}
	_ = response.Body.Close()
}

func TestCertificateReloadRetainsLastValidConfiguration(t *testing.T) {
	directory := t.TempDir()
	first := writeCertificateMaterial(t, directory, "one")
	metrics := telemetry.NewMetrics()
	source := security.NewCertificateSource(first.bootstrap, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics)
	if err := source.Reload(); err != nil {
		t.Fatalf("Reload(first) error = %v", err)
	}
	firstDER := append([]byte(nil), source.Current().Certificates[0].Certificate[0]...)

	second := writeCertificateMaterial(t, directory, "two")
	if second.bootstrap != first.bootstrap {
		t.Fatal("test bootstrap path changed")
	}
	if err := source.Reload(); err != nil {
		t.Fatalf("Reload(second) error = %v", err)
	}
	secondDER := source.Current().Certificates[0].Certificate[0]
	if string(firstDER) == string(secondDER) {
		t.Fatal("certificate did not change after reload")
	}

	if err := os.WriteFile(second.key, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.Reload(); err == nil {
		t.Fatal("Reload(invalid) error = nil, want error")
	}
	if got := source.Current().Certificates[0].Certificate[0]; string(got) != string(secondDER) {
		t.Fatal("invalid reload replaced the last valid certificate")
	}
}

func TestAdminHandlerReportsReadinessAndMetrics(t *testing.T) {
	metrics := telemetry.NewMetrics()
	server := &Server{metrics: metrics, policy: policy.NewSource("", 0, policy.ModeStrict, slog.Default(), metrics)}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	server.ready.Store(true)
	response = httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", response.Code, http.StatusOK)
	}

	response = httptest.NewRecorder()
	server.adminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), "dxproxy_connections_opened_total") {
		t.Fatalf("metrics response missing connection metric: %s", response.Body.String())
	}
}

func startTestServer(t *testing.T, config Config, _ certificateMaterial) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.ListenAddress = listener.Addr().String()
	config.AdminAddress = ""
	config.MaxConnections = 100
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
	stop := func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("server shutdown error = %v", err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}
	return server, listener.Addr().String(), stop
}

type certificateMaterial struct {
	bootstrap  string
	key        string
	rootPool   *x509.CertPool
	clientCert tls.Certificate
}

func (m certificateMaterial) client() *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      m.rootPool,
			ServerName:   "dxproxy.test",
			Certificates: []tls.Certificate{m.clientCert},
		},
	}}
}

func writeCertificateMaterial(t *testing.T, directory, name string) certificateMaterial {
	t.Helper()
	caCert, caKey := newTestCA(t, name)
	serverCert, serverKey := newSignedCertificate(t, caCert, caKey, "dxproxy.test")
	clientCert, clientKey := newSignedCertificate(t, caCert, caKey, "client.test")
	certPath := filepath.Join(directory, "cert-chain.pem")
	keyPath := filepath.Join(directory, "key.pem")
	rootPath := filepath.Join(directory, "root-cert.pem")
	clientCertPath := filepath.Join(directory, "client-cert.pem")
	clientKeyPath := filepath.Join(directory, "client-key.pem")
	writePEMFile(t, certPath, "CERTIFICATE", serverCert.Raw)
	writePEMFile(t, keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	writePEMFile(t, rootPath, "CERTIFICATE", caCert.Raw)
	writePEMFile(t, clientCertPath, "CERTIFICATE", clientCert.Raw)
	writePEMFile(t, clientKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))
	bootstrapPath := filepath.Join(directory, "grpc-bootstrap.json")
	bootstrap := map[string]any{
		"xds_servers": []map[string]any{{"server_uri": "dubbod.test:26012"}},
		"certificate_providers": map[string]any{
			"default": map[string]any{
				"plugin_name": "file_watcher",
				"config": map[string]string{
					"certificate_file":    certPath,
					"private_key_file":    keyPath,
					"ca_certificate_file": rootPath,
				},
			},
		},
	}
	data, err := json.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bootstrapPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	clientPair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return certificateMaterial{bootstrap: bootstrapPath, key: keyPath, rootPool: pool, clientCert: clientPair}
}

func newTestCA(t *testing.T, name string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "ca-" + name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newSignedCertificate(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, commonName string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{
		ListenAddress:         ":15080",
		UpstreamAddress:       "127.0.0.1:8080",
		BootstrapPath:         "/bootstrap.json",
		DefaultMode:           string(policy.ModeStrict),
		HandshakeTimeout:      time.Second,
		ConnectTimeout:        time.Second,
		ConfigRefreshInterval: time.Second,
		MaxConnections:        1,
	}
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"same admin address", func(config *Config) { config.AdminAddress = config.ListenAddress }},
		{"missing upstream host", func(config *Config) { config.UpstreamAddress = ":8080" }},
		{"invalid mode", func(config *Config) { config.DefaultMode = "bad" }},
		{"negative connections", func(config *Config) { config.MaxConnections = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.edit(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
		})
	}
	disable := base
	disable.ModeOverride = string(policy.ModeDisable)
	disable.BootstrapPath = ""
	if err := disable.Validate(); err != nil {
		t.Fatalf("DISABLE without bootstrap should be valid: %v", err)
	}
}
