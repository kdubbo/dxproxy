// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"bytes"
	"strings"
	"testing"
)

func TestRequestCountRespectsResponseStatusOverride(t *testing.T) {
	metrics := NewMetrics()
	metrics.Configure(Config{RequestCountEnabled: true})
	metrics.RequestCompleted("0")
	metrics.RequestCompleted("7")

	var output bytes.Buffer
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `dubbo_inherent_requests_total{reporter="server",grpc_response_status="0"} 1`) ||
		!strings.Contains(output.String(), `dubbo_inherent_requests_total{reporter="server",grpc_response_status="7"} 1`) {
		t.Fatalf("request metrics =\n%s", output.String())
	}

	metrics.Configure(Config{RequestCountEnabled: true, RemoveGRPCResponseStatus: true})
	output.Reset()
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `dubbo_inherent_requests_total{reporter="server"} 2`) ||
		strings.Contains(output.String(), "grpc_response_status") {
		t.Fatalf("request metrics after REMOVE =\n%s", output.String())
	}
}

func TestDisabledRequestCountIsNotRecordedOrExported(t *testing.T) {
	metrics := NewMetrics()
	metrics.RequestCompleted("0")

	var output bytes.Buffer
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "dubbo_inherent_requests_total") {
		t.Fatalf("disabled request metric exported:\n%s", output.String())
	}
}
