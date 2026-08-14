// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package proxy

import (
	"io"
	"strings"

	"github.com/kdubbo/dxproxy/pkg/telemetry"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type grpcResponseObserver struct {
	writer *io.PipeWriter
	done   chan struct{}
}

func newGRPCResponseObserver(metrics *telemetry.Metrics) *grpcResponseObserver {
	reader, writer := io.Pipe()
	observer := &grpcResponseObserver{writer: writer, done: make(chan struct{})}
	go func() {
		defer close(observer.done)
		if observeGRPCResponses(reader, metrics) != nil {
			// Parsing must never break the proxied connection. Drain remaining
			// bytes so the writer keeps forwarding after malformed/non-gRPC data.
			_, _ = io.Copy(io.Discard, reader)
		}
		_ = reader.Close()
	}()
	return observer
}

func (o *grpcResponseObserver) Write(data []byte) (int, error) {
	return o.writer.Write(data)
}

func (o *grpcResponseObserver) Close() {
	_ = o.writer.Close()
	<-o.done
}

func observeGRPCResponses(reader io.Reader, metrics *telemetry.Metrics) error {
	framer := http2.NewFramer(io.Discard, reader)
	framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	grpcStreams := make(map[uint32]bool)

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return err
		}
		switch frame := frame.(type) {
		case *http2.MetaHeadersFrame:
			status := ""
			for _, field := range frame.Fields {
				switch field.Name {
				case "content-type":
					if strings.HasPrefix(strings.ToLower(field.Value), "application/grpc") {
						grpcStreams[frame.StreamID] = true
					}
				case "grpc-status":
					status = field.Value
				}
			}
			if frame.StreamEnded() && grpcStreams[frame.StreamID] {
				metrics.RequestCompleted(status)
				delete(grpcStreams, frame.StreamID)
			}
		case *http2.DataFrame:
			if frame.StreamEnded() && grpcStreams[frame.StreamID] {
				metrics.RequestCompleted("")
				delete(grpcStreams, frame.StreamID)
			}
		case *http2.RSTStreamFrame:
			if grpcStreams[frame.StreamID] {
				metrics.RequestCompleted("1")
				delete(grpcStreams, frame.StreamID)
			}
		}
	}
}
