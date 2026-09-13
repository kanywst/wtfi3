BINARY  := wtfi3
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test lint fmt run clean sample

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

## sample: generate a synthetic capture for offline testing
sample:
	go run hack/gensample.go /tmp/wtfi3-sample.pcap

## run: replay the sample capture (no root needed)
run: build sample
	./$(BINARY) -r /tmp/wtfi3-sample.pcap

clean:
	rm -f $(BINARY)
	rm -rf dist
