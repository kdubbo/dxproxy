// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kdubbo/dxplane/pkg/policy"
	"github.com/kdubbo/dxplane/pkg/proxy"
)

const defaultRuntimeConfigPath = "/etc/dubbo/proxy/dubbo-grpc-xds.json"

func run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			_, err := fmt.Fprintln(stdout, version)
			return err
		case "inbound", "grpc-inbound":
			args = args[1:]
		}
	}

	cfg := proxy.Config{
		ListenAddress:         firstNonEmpty(os.Getenv("DUBBO_GRPC_INBOUND_LISTEN"), ":15080"),
		UpstreamAddress:       firstNonEmpty(os.Getenv("DUBBO_GRPC_INBOUND_UPSTREAM"), "127.0.0.1:80"),
		BootstrapPath:         os.Getenv("GRPC_XDS_BOOTSTRAP"),
		RuntimeConfigPath:     firstNonEmpty(os.Getenv("DUBBO_GRPC_XDS_CONFIG"), defaultRuntimeConfigPath),
		ModeOverride:          os.Getenv("DUBBO_GRPC_INBOUND_MTLS_MODE"),
		DefaultMode:           firstNonEmpty(os.Getenv("DUBBO_GRPC_INBOUND_DEFAULT_MTLS_MODE"), string(policy.ModeStrict)),
		PolicyPort:            intFromEnv("DUBBO_GRPC_INBOUND_POLICY_PORT", 0),
		HandshakeTimeout:      durationFromEnv("DUBBO_GRPC_INBOUND_HANDSHAKE_TIMEOUT", 10*time.Second),
		ConnectTimeout:        durationFromEnv("DUBBO_GRPC_INBOUND_CONNECT_TIMEOUT", 5*time.Second),
		ConfigRefreshInterval: durationFromEnv("DUBBO_GRPC_INBOUND_CONFIG_REFRESH_INTERVAL", time.Second),
		AdminAddress:          firstNonEmpty(os.Getenv("DUBBO_GRPC_INBOUND_ADMIN_ADDRESS"), ":15020"),
		MaxConnections:        intFromEnv("DUBBO_GRPC_INBOUND_MAX_CONNECTIONS", 10_000),
		// 5s + 25s fits inside the 30s default terminationGracePeriodSeconds, so
		// the drain finishes before kubelet escalates to SIGKILL.
		TerminationDrainDelay:    durationFromEnv("DUBBO_GRPC_INBOUND_TERMINATION_DRAIN_DELAY", 5*time.Second),
		TerminationDrainDuration: durationFromEnv("DUBBO_GRPC_INBOUND_TERMINATION_DRAIN_DURATION", 25*time.Second),
	}

	flags := flag.NewFlagSet("dxplane", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.ListenAddress, "listen", cfg.ListenAddress, "inbound listener address")
	flags.StringVar(&cfg.UpstreamAddress, "upstream", cfg.UpstreamAddress, "local plaintext upstream address")
	flags.StringVar(&cfg.BootstrapPath, "bootstrap", cfg.BootstrapPath, "gRPC xDS bootstrap file")
	flags.StringVar(&cfg.RuntimeConfigPath, "runtime-config", cfg.RuntimeConfigPath, "proxyless runtime policy file; empty disables runtime policy reload")
	flags.StringVar(&cfg.ModeOverride, "mtls-mode", cfg.ModeOverride, "override inbound mTLS mode: DISABLE, PERMISSIVE, or STRICT")
	flags.StringVar(&cfg.DefaultMode, "default-mtls-mode", cfg.DefaultMode, "fail-safe mTLS mode before runtime policy is available")
	flags.IntVar(&cfg.PolicyPort, "policy-port", cfg.PolicyPort, "optional Service port used to select inbound policy")
	flags.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", cfg.HandshakeTimeout, "TLS classification and handshake timeout")
	flags.DurationVar(&cfg.ConnectTimeout, "connect-timeout", cfg.ConnectTimeout, "local upstream connection timeout")
	flags.DurationVar(&cfg.ConfigRefreshInterval, "config-refresh-interval", cfg.ConfigRefreshInterval, "certificate and runtime policy refresh interval")
	flags.StringVar(&cfg.AdminAddress, "admin-address", cfg.AdminAddress, "health, readiness, and metrics listener; empty disables it")
	flags.IntVar(&cfg.MaxConnections, "max-connections", cfg.MaxConnections, "maximum concurrent inbound connections; zero is unlimited")
	flags.DurationVar(&cfg.TerminationDrainDelay, "termination-drain-delay", cfg.TerminationDrainDelay, "time spent failing readiness while still accepting, so the endpoint is withdrawn before the listener closes")
	flags.DurationVar(&cfg.TerminationDrainDuration, "termination-drain-duration", cfg.TerminationDrainDuration, "maximum time in-flight connections may run after the listener closes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	server, err := proxy.NewServer(cfg, logger)
	if err != nil {
		return err
	}
	return server.Run(ctx)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func intFromEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
