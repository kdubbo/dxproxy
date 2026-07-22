// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kdubbo/dxplane/pkg/telemetry"
)

const RuntimeConfigVersion = "dubbo.apache.org/proxyless-grpc/v1"

type Mode string

const (
	ModeDisable    Mode = "DISABLE"
	ModePermissive Mode = "PERMISSIVE"
	ModeStrict     Mode = "STRICT"
)

func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToUpper(strings.TrimSpace(value))) {
	case ModeDisable:
		return ModeDisable, nil
	case ModePermissive:
		return ModePermissive, nil
	case ModeStrict:
		return ModeStrict, nil
	default:
		return "", fmt.Errorf("unsupported value %q; want DISABLE, PERMISSIVE, or STRICT", value)
	}
}

func ParseOptionalMode(value string) (Mode, bool, error) {
	if strings.TrimSpace(value) == "" {
		return "", false, nil
	}
	mode, err := ParseMode(value)
	return mode, err == nil, err
}

type runtimeConfig struct {
	Version  string `json:"version"`
	Workload struct {
		PodIP string `json:"podIP"`
	} `json:"workload"`
	Services []runtimeService `json:"services"`
}

type runtimeService struct {
	Host      string        `json:"host"`
	Ports     []runtimePort `json:"ports"`
	Endpoints []struct {
		Address string `json:"address"`
	} `json:"endpoints"`
}

type runtimePort struct {
	Port     int    `json:"port"`
	MTLSMode string `json:"mtlsMode"`
}

func modeFromRuntimeConfig(data []byte, policyPort int) (Mode, error) {
	var cfg runtimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("parse runtime config: %w", err)
	}
	if cfg.Version != "" && cfg.Version != RuntimeConfigVersion {
		return "", fmt.Errorf("unsupported runtime config version %q", cfg.Version)
	}

	services := workloadServices(cfg)
	best := Mode("")
	for _, service := range services {
		for _, port := range service.Ports {
			if policyPort != 0 && port.Port != policyPort {
				continue
			}
			mode, err := ParseMode(port.MTLSMode)
			if err != nil {
				if strings.TrimSpace(port.MTLSMode) == "" {
					continue
				}
				return "", fmt.Errorf("service %q port %d: %w", service.Host, port.Port, err)
			}
			if modePriority(mode) > modePriority(best) {
				best = mode
			}
		}
	}
	if best == "" {
		if policyPort != 0 {
			return "", fmt.Errorf("no inbound mTLS policy found for workload service port %d", policyPort)
		}
		return "", fmt.Errorf("no inbound mTLS policy found for workload services")
	}
	return best, nil
}

func workloadServices(cfg runtimeConfig) []runtimeService {
	podIP := strings.TrimSpace(cfg.Workload.PodIP)
	if podIP == "" {
		return cfg.Services
	}
	selected := make([]runtimeService, 0)
	for _, service := range cfg.Services {
		for _, endpoint := range service.Endpoints {
			if endpoint.Address == podIP {
				selected = append(selected, service)
				break
			}
		}
	}
	return selected
}

func modePriority(mode Mode) int {
	switch mode {
	case ModeStrict:
		return 3
	case ModePermissive:
		return 2
	case ModeDisable:
		return 1
	default:
		return 0
	}
}

type Source struct {
	path       string
	policyPort int
	logger     *slog.Logger
	metrics    *telemetry.Metrics

	current atomic.Value
	loaded  atomic.Bool
	mu      sync.Mutex
	lastErr string
}

func NewSource(path string, policyPort int, fallback Mode, logger *slog.Logger, metrics *telemetry.Metrics) *Source {
	source := &Source{path: path, policyPort: policyPort, logger: logger, metrics: metrics}
	source.current.Store(fallback)
	if path == "" {
		source.loaded.Store(true)
	}
	return source
}

func (s *Source) Mode() Mode {
	return s.current.Load().(Mode)
}

func (s *Source) Loaded() bool {
	return s.loaded.Load()
}

func (s *Source) Reload() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return s.recordError(fmt.Errorf("read runtime config %s: %w", s.path, err))
	}
	mode, err := modeFromRuntimeConfig(data, s.policyPort)
	if err != nil {
		return s.recordError(err)
	}
	previous := s.Mode()
	s.current.Store(mode)
	s.loaded.Store(true)
	s.recordRecovery()
	if previous != mode {
		s.logger.Info("inbound mTLS policy updated", "previous", previous, "current", mode)
	}
	return nil
}

func (s *Source) Run(ctx context.Context, interval time.Duration) {
	if s.path == "" {
		return
	}
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

func (s *Source) recordError(err error) error {
	s.metrics.ConfigReloadFailed()
	s.mu.Lock()
	defer s.mu.Unlock()
	if message := err.Error(); message != s.lastErr {
		s.logger.Error("runtime policy reload failed; retaining last valid mode", "error", err)
		s.lastErr = message
	}
	return err
}

func (s *Source) recordRecovery() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != "" {
		s.logger.Info("runtime policy reload recovered")
		s.lastErr = ""
	}
}

func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
