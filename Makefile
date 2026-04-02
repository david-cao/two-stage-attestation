.PHONY: all agent agent-linux proto image clean test test-e2e

all: agent-linux

# Build the attestation agent for the host platform.
agent:
	cd agent && go build -o ../bin/attestation-agent ./cmd/attestation-agent

# Cross-compile the attestation agent for Linux (for the VM image).
agent-linux:
	cd agent && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags="-s -w" \
		-o ../bin/attestation-agent-linux ./cmd/attestation-agent

# Generate Go code from proto files.
proto:
	protoc \
		--go_out=agent --go_opt=paths=source_relative \
		--go-grpc_out=agent --go-grpc_opt=paths=source_relative \
		agent/api/v1/agent.proto

# Build the VM image with mkosi (run on a Linux machine).
image: agent-linux
	cp bin/attestation-agent-linux image/mkosi.extra/usr/bin/attestation-agent
	cd image && sudo mkosi build

# Build the verification CLI.
verify:
	cd verify && go build -o ../bin/verify-quote ./cmd/verify-quote

# Run unit tests.
test:
	cd agent && go test ./...
	cd verify && go test ./...

# Run end-to-end tests against a running agent (use on TDX CVM).
test-e2e: agent verify
	./scripts/test-e2e.sh

clean:
	rm -rf bin/
	cd image && sudo mkosi clean || true
