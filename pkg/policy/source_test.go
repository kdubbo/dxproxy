// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/kdubbo/dxplane/pkg/telemetry"
)

func TestModeFromRuntimeConfigSelectsWorkloadServices(t *testing.T) {
	config := runtimeConfig{Version: RuntimeConfigVersion}
	config.Workload.PodIP = "10.0.0.10"
	config.Services = []runtimeService{
		serviceWithPolicy("local.default.svc", "10.0.0.10", 80, "PERMISSIVE"),
		serviceWithPolicy("unrelated.default.svc", "10.0.0.20", 80, "STRICT"),
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	mode, err := modeFromRuntimeConfig(data, 0)
	if err != nil {
		t.Fatalf("modeFromRuntimeConfig() error = %v", err)
	}
	if mode != ModePermissive {
		t.Fatalf("mode = %q, want %q", mode, ModePermissive)
	}
}

func TestModeFromRuntimeConfigUsesPolicyPortAndStrictestConflict(t *testing.T) {
	config := runtimeConfig{}
	config.Workload.PodIP = "10.0.0.10"
	service := serviceWithPolicy("local.default.svc", "10.0.0.10", 80, "DISABLE")
	service.Ports = append(service.Ports, runtimePort{Port: 8080, MTLSMode: "STRICT"})
	config.Services = []runtimeService{service}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	mode, err := modeFromRuntimeConfig(data, 80)
	if err != nil {
		t.Fatalf("modeFromRuntimeConfig(port 80) error = %v", err)
	}
	if mode != ModeDisable {
		t.Fatalf("port 80 mode = %q, want %q", mode, ModeDisable)
	}
	mode, err = modeFromRuntimeConfig(data, 0)
	if err != nil {
		t.Fatalf("modeFromRuntimeConfig(all ports) error = %v", err)
	}
	if mode != ModeStrict {
		t.Fatalf("all-port mode = %q, want strictest %q", mode, ModeStrict)
	}
}

func TestModeFromRuntimeConfigRejectsUnknownVersionAndMode(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"version", `{"version":"dubbo.apache.org/proxyless-grpc/v2"}`},
		{"mode", `{"services":[{"host":"bad","ports":[{"port":80,"mtlsMode":"UNKNOWN"}]}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := modeFromRuntimeConfig([]byte(test.data), 0); err == nil {
				t.Fatal("modeFromRuntimeConfig() error = nil, want error")
			}
		})
	}
}

func TestPolicySourceRetainsLastValidMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	writeRuntimePolicy(t, path, ModePermissive)
	source := NewSource(path, 0, ModeStrict, slog.New(slog.NewTextHandler(io.Discard, nil)), telemetry.NewMetrics())
	if err := source.Reload(); err != nil {
		t.Fatalf("Reload(valid) error = %v", err)
	}
	if source.Mode() != ModePermissive {
		t.Fatalf("mode = %q, want %q", source.Mode(), ModePermissive)
	}
	if err := os.WriteFile(path, []byte(`{"services":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.Reload(); err == nil {
		t.Fatal("Reload(invalid) error = nil, want error")
	}
	if source.Mode() != ModePermissive {
		t.Fatalf("mode after invalid reload = %q, want last valid %q", source.Mode(), ModePermissive)
	}
}

func ExampleMode() {
	mode, _ := ParseMode("strict")
	fmt.Println(mode)
	// Output: STRICT
}

func serviceWithPolicy(host, endpoint string, port int, mode string) runtimeService {
	service := runtimeService{Host: host, Ports: []runtimePort{{Port: port, MTLSMode: mode}}}
	service.Endpoints = append(service.Endpoints, struct {
		Address string `json:"address"`
	}{Address: endpoint})
	return service
}

func writeRuntimePolicy(t *testing.T, path string, mode Mode) {
	t.Helper()
	config := runtimeConfig{Version: RuntimeConfigVersion}
	config.Services = []runtimeService{serviceWithPolicy("local.default.svc", "10.0.0.10", 80, string(mode))}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
