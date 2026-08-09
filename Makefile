# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0.

.PHONY: build test test-race vet fmt check docker-build clean

GIT_VERSION ?= dev
IMAGE ?= kdubbo/dxproxy:dev

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(GIT_VERSION)" -o bin/dxproxy ./cmd

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	find . -name '*.go' -not -path './vendor/*' -print0 | xargs -0 gofmt -w

check: test-race vet
	test -z "$$(find . -name '*.go' -not -path './vendor/*' -print0 | xargs -0 gofmt -l)"
	go mod tidy -diff
	git diff --check

docker-build:
	docker build --build-arg GIT_VERSION=$(GIT_VERSION) -t $(IMAGE) .

clean:
	rm -rf bin coverage.out
