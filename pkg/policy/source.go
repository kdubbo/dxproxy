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

	"github.com/kdubbo/dxproxy/pkg/telemetry"
)

const RuntimeConfigVersion = "dubbo.apache.org/inherent-grpc/v1"

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
	Port     int               `json:"port"`
	MTLSMode string            `json:"mtlsMode"`
	Fault    *runtimePortFault `json:"fault"`
}

type runtimePortFault struct {
	Delay *runtimeFaultDelay `json:"delay"`
	Abort *runtimeFaultAbort `json:"abort"`
}

type runtimeFaultDelay struct {
	FixedDelay string `json:"fixedDelay"`
	Percentage uint32 `json:"percentage"`
}

type runtimeFaultAbort struct {
	HTTPStatus uint32 `json:"httpStatus"`
	Percentage uint32 `json:"percentage"`
}

type Fault struct {
	Delay           time.Duration
	DelayPercentage uint32
	AbortStatus     uint32
	AbortPercentage uint32
}

type State struct {
	Mode  Mode
	Fault Fault
}

func stateFromRuntimeConfig(data []byte, policyPort int) (State, error) {
	var cfg runtimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return State{}, fmt.Errorf("parse runtime config: %w", err)
	}
	if cfg.Version != "" && cfg.Version != RuntimeConfigVersion {
		return State{}, fmt.Errorf("unsupported runtime config version %q", cfg.Version)
	}

	services := workloadServices(cfg)
	best := Mode("")
	var selectedFault *Fault
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
				return State{}, fmt.Errorf("service %q port %d: %w", service.Host, port.Port, err)
			}
			if modePriority(mode) > modePriority(best) {
				best = mode
			}
			fault, err := parseRuntimeFault(port.Fault)
			if err != nil {
				return State{}, fmt.Errorf("service %q port %d: %w", service.Host, port.Port, err)
			}
			if fault != (Fault{}) {
				if selectedFault != nil && *selectedFault != fault {
					return State{}, fmt.Errorf("conflicting inbound fault policies for workload service port %d", port.Port)
				}
				copy := fault
				selectedFault = &copy
			}
		}
	}
	if best == "" {
		if policyPort != 0 {
			return State{}, fmt.Errorf("no inbound mTLS policy found for workload service port %d", policyPort)
		}
		return State{}, fmt.Errorf("no inbound mTLS policy found for workload services")
	}
	state := State{Mode: best}
	if selectedFault != nil {
		state.Fault = *selectedFault
	}
	return state, nil
}

func modeFromRuntimeConfig(data []byte, policyPort int) (Mode, error) {
	state, err := stateFromRuntimeConfig(data, policyPort)
	return state.Mode, err
}

func parseRuntimeFault(raw *runtimePortFault) (Fault, error) {
	if raw == nil {
		return Fault{}, nil
	}
	fault := Fault{}
	if raw.Delay != nil {
		delay, err := time.ParseDuration(raw.Delay.FixedDelay)
		if err != nil || delay <= 0 {
			return Fault{}, fmt.Errorf("fault.delay.fixedDelay must be a positive duration")
		}
		if raw.Delay.Percentage > 100 {
			return Fault{}, fmt.Errorf("fault.delay.percentage must be in range [0, 100]")
		}
		fault.Delay = delay
		fault.DelayPercentage = raw.Delay.Percentage
	}
	if raw.Abort != nil {
		if raw.Abort.HTTPStatus < 400 || raw.Abort.HTTPStatus > 599 {
			return Fault{}, fmt.Errorf("fault.abort.httpStatus must be in range [400, 599]")
		}
		if raw.Abort.Percentage > 100 {
			return Fault{}, fmt.Errorf("fault.abort.percentage must be in range [0, 100]")
		}
		fault.AbortStatus = raw.Abort.HTTPStatus
		fault.AbortPercentage = raw.Abort.Percentage
	}
	return fault, nil
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
	source.current.Store(State{Mode: fallback})
	if path == "" {
		source.loaded.Store(true)
	}
	return source
}

func (s *Source) Mode() Mode {
	return s.current.Load().(State).Mode
}

func (s *Source) Fault() Fault {
	return s.current.Load().(State).Fault
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
	state, err := stateFromRuntimeConfig(data, s.policyPort)
	if err != nil {
		return s.recordError(err)
	}
	previous := s.Mode()
	s.current.Store(state)
	s.loaded.Store(true)
	s.recordRecovery()
	if previous != state.Mode {
		s.logger.Info("inbound mTLS policy updated", "previous", previous, "current", state.Mode)
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
