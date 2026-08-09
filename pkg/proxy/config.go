// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kdubbo/dxproxy/pkg/policy"
)

type Config struct {
	ListenAddress         string
	UpstreamAddress       string
	BootstrapPath         string
	RuntimeConfigPath     string
	ModeOverride          string
	DefaultMode           string
	PolicyPort            int
	HandshakeTimeout      time.Duration
	ConnectTimeout        time.Duration
	ConfigRefreshInterval time.Duration
	AdminAddress          string
	MaxConnections        int

	// TerminationDrainDelay is how long the pod keeps accepting connections
	// after reporting not-ready, giving the EndpointSlice controller and every
	// caller's EDS time to drop this endpoint before the listener disappears.
	TerminationDrainDelay time.Duration
	// TerminationDrainDuration bounds how long in-flight connections may run
	// after the listener closes. Whatever is left when it expires is cut.
	TerminationDrainDuration time.Duration
}

func (c Config) Validate() error {
	if err := validateAddress("listen", c.ListenAddress, true, true); err != nil {
		return err
	}
	if err := validateAddress("upstream", c.UpstreamAddress, false, false); err != nil {
		return err
	}
	if c.AdminAddress != "" {
		if err := validateAddress("admin", c.AdminAddress, true, true); err != nil {
			return err
		}
		if c.AdminAddress == c.ListenAddress {
			return fmt.Errorf("admin address must differ from listen address")
		}
	}
	if c.PolicyPort < 0 || c.PolicyPort > 65535 {
		return fmt.Errorf("policy port must be between 0 and 65535")
	}
	if c.HandshakeTimeout <= 0 {
		return fmt.Errorf("handshake timeout must be greater than zero")
	}
	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be greater than zero")
	}
	if c.ConfigRefreshInterval <= 0 {
		return fmt.Errorf("config refresh interval must be greater than zero")
	}
	if c.MaxConnections < 0 {
		return fmt.Errorf("max connections cannot be negative")
	}
	if c.TerminationDrainDelay < 0 {
		return fmt.Errorf("termination drain delay cannot be negative")
	}
	if c.TerminationDrainDuration < 0 {
		return fmt.Errorf("termination drain duration cannot be negative")
	}
	modeOverride, hasOverride, err := policy.ParseOptionalMode(c.ModeOverride)
	if err != nil {
		return fmt.Errorf("mTLS mode override: %w", err)
	}
	if _, err := policy.ParseMode(c.DefaultMode); err != nil {
		return fmt.Errorf("default mTLS mode: %w", err)
	}
	if (!hasOverride || modeOverride != policy.ModeDisable) && strings.TrimSpace(c.BootstrapPath) == "" {
		return fmt.Errorf("bootstrap path is required unless mTLS mode is explicitly DISABLE")
	}
	return nil
}

func validateAddress(name, address string, allowEmptyHost, allowZeroPort bool) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("%s address is required", name)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid %s address %q: %w", name, address, err)
	}
	if !allowEmptyHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid %s address %q: host is required", name, address)
	}
	if port == "" {
		return fmt.Errorf("invalid %s address %q: port is required", name, address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 || (!allowZeroPort && portNumber == 0) {
		return fmt.Errorf("invalid %s address %q: port must be an integer between 1 and 65535", name, address)
	}
	return nil
}
