// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kdubbo/dxproxy/pkg/telemetry"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestObserveGRPCResponsesCountsCompletedStreams(t *testing.T) {
	var wire bytes.Buffer
	framer := http2.NewFramer(&wire, nil)
	writeHeaders := func(streamID uint32, endStream bool, fields ...hpack.HeaderField) {
		t.Helper()
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		for _, field := range fields {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: block.Bytes(),
			EndStream:     endStream,
			EndHeaders:    true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	writeHeaders(1, false,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/grpc"},
	)
	writeHeaders(1, true, hpack.HeaderField{Name: "grpc-status", Value: "7"})

	metrics := telemetry.NewMetrics()
	metrics.Configure(telemetry.Config{RequestCountEnabled: true})
	if err := observeGRPCResponses(bytes.NewReader(wire.Bytes()), metrics); !errors.Is(err, io.EOF) {
		t.Fatalf("observeGRPCResponses() error = %v, want EOF", err)
	}

	var output bytes.Buffer
	if err := metrics.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `grpc_response_status="7"} 1`) {
		t.Fatalf("request metrics =\n%s", output.String())
	}
}
