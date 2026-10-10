BINARY  := wtfi3
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test lint fmt run clean sample demo

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/wtfi3

test:
	go test ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

## sample: generate a synthetic capture for offline testing
sample:
	go run hack/gensample.go /tmp/wtfi3-sample.pcap

## demo: serve the dashboard on synthetic live traffic (no root, no network)
demo:
	go run hack/demo.go

## run: replay the sample capture (no root needed)
run: build sample
	./$(BINARY) -r /tmp/wtfi3-sample.pcap

clean:
	rm -f $(BINARY)
	rm -rf dist
