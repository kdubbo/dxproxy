// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"version"}, "1.2.3", &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run(version) error = %v", err)
	}
	if stdout.String() != "1.2.3\n" {
		t.Fatalf("version output = %q, want %q", stdout.String(), "1.2.3\\n")
	}
}

func TestRunAcceptsLegacyCommandAlias(t *testing.T) {
	err := run(context.Background(), []string{"grpc-inbound", "--help"}, "dev", &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(grpc-inbound --help) error = %v, want flag.ErrHelp", err)
	}
}

func TestRunRejectsUnexpectedArguments(t *testing.T) {
	err := run(context.Background(), []string{"unexpected"}, "dev", &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("run(unexpected) error = nil, want error")
	}
}
