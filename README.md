# TDX Two-Stage Attestation

A two-stage attestation system for Intel TDX. Stage 1 is a reusable base VM image (kernel, container runtime, attestation agent) measured into MRTD + RTMR[0-1]. Stage 2 is an arbitrary OCI container whose manifest digest is measured into RTMR[2] before execution. A remote verifier checks all measurements to get cryptographic assurance of what's running.

See `two_stage.md` for the full design.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Trust Domain (TD)                              │
│                                                 │
│  ┌──────────────────────────────────────────┐   │
│  │ Base Image (Stage 1)                     │   │
│  │  TDVF firmware        → MRTD, RTMR[0]   │   │
│  │  UKI (kernel+initrd)  → RTMR[1]         │   │
│  │  dm-verity rootfs                        │   │
│  │  attestation-agent (vsock :4050)         │   │
│  └──────────────────────────────────────────┘   │
│                     │                           │
│                     │ LaunchContainer RPC       │
│                     ▼                           │
│  ┌──────────────────────────────────────────┐   │
│  │ Workload Container (Stage 2)             │   │
│  │  OCI manifest digest  → RTMR[2]         │   │
│  │  podman run ...                          │   │
│  └──────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
         ▲ vsock
         │
    Host / Orchestrator
         │
         ▼
   ┌────────────┐
   │ verify-quote│  checks MRTD + RTMR[0-2] against policy
   └────────────┘
```

## Project Structure

```
agent/                          Go attestation agent
├── api/v1/agent.proto          gRPC service definition
├── cmd/attestation-agent/      entry point (vsock/TCP listener)
└── internal/
    ├── attestation/            RTMR extension, quote generation, RA-TLS, mocks
    ├── container/              podman image pull/inspect, container run/stop
    ├── measure/                OCI digest → 48-byte RTMR value
    └── server/                 gRPC handler implementations

image/                          mkosi VM image build
├── mkosi.conf                  Fedora 41, UKI, dm-verity
├── mkosi.conf.d/               package groups (base, container, agent)
├── mkosi.extra/                rootfs overlay (systemd service, config)
├── mkosi.build                 compiles the Go agent
└── mkosi.finalize              strips docs/caches

verify/                         quote verification CLI
├── cmd/verify-quote/           CLI entry point
└── internal/policy/            policy file loading and checking

scripts/
├── run-qemu.sh                 boot image in QEMU (no TDX)
├── run-td.sh                   boot as TD on TDX hardware
└── compute-reference.sh        compute expected MRTD/RTMR values
```

## gRPC API

| RPC | Purpose |
|-----|---------|
| `LaunchContainer` | Pull OCI image, measure manifest digest into RTMR[2], start container |
| `GetQuote` | Generate TDX quote with 64 bytes of caller-supplied report data |
| `GetRATLSCredentials` | Ephemeral TLS keypair with quote embedded in X.509 cert |
| `GetStatus` | Health check, reports TDX hardware availability |

## Prerequisites

- **Go 1.22+** — agent and verify builds
- **protoc** + `protoc-gen-go` + `protoc-gen-go-grpc` — only if regenerating proto stubs
- **mkosi** — VM image build (Linux only)
- **podman** — container runtime (inside the VM, or on the dev machine for local testing)
- **QEMU** — booting the image locally
- **TDX hardware** — only for real attestation (Azure DCesv5, GCP C3, or bare-metal)

## Building

```bash
# Build the agent for macOS (development)
make agent

# Cross-compile the agent for Linux (for the VM image)
make agent-linux

# Build the verification CLI
make verify

# Regenerate protobuf stubs (only needed if you change agent.proto)
make proto

# Build the VM image (run on a Linux machine with mkosi installed)
make image
```

## Testing

### Unit tests (no hardware needed)

```bash
make test
```

This runs tests for:
- `agent/internal/attestation/` — mock RTMR extender and quote generator
- `agent/internal/measure/` — digest parsing, SHA-384 padding, RTMR extension math
- `verify/internal/policy/` — policy matching logic

### Local agent testing (no TDX, no VM)

Run the agent on your dev machine with TCP transport. It auto-detects missing TDX hardware and falls back to mock attestation backends.

```bash
# Terminal 1: start the agent
go run ./agent/cmd/attestation-agent --listen tcp://localhost:4050

# Terminal 2: call RPCs with grpcurl
grpcurl -plaintext localhost:4050 attestation.agent.v1.AttestationAgent/GetStatus
```

If you have podman installed, you can test the full container launch flow:

```bash
grpcurl -plaintext -d '{
  "image_ref": "docker.io/library/alpine:latest",
  "command": ["echo", "hello from measured container"]
}' localhost:4050 attestation.agent.v1.AttestationAgent/LaunchContainer
```

### [Linux Only] QEMU boot test (no TDX)

Build the image on a Linux machine, then boot it in QEMU:

```bash
make image
./scripts/run-qemu.sh
```

Inside the VM, the agent starts automatically via systemd. From the host, connect over vsock (CID 3, port 4050).

### Cloud CVM testing (Azure DCesv5 / GCP C3)

Test the agent on real TDX hardware using a cloud provider's CVM. This tests RTMR[2] extension, quote generation, and verification — but not the custom mkosi image boot chain.

```bash
# 1. Provision a TDX CVM:
#    Azure:  az vm create --size Standard_DCes_v5 --image Canonical:ubuntu-24_04-lts:cvm:latest --security-type ConfidentialVM
gcloud compute instances create <INSTANCE-NAME> \
    --confidential-compute-type=TDX \
    --machine-type=c3-standard-4 \
    --maintenance-policy="TERMINATE" \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-2404-lts-amd64

# 2. SSH in, clone repo, and run setup:
./scripts/setup-cvm.sh

# 3. Start the agent:
./bin/attestation-agent --listen tcp://localhost:4050

# 4. In another terminal, run the E2E tests:
./scripts/test-e2e.sh
# Or: make test-e2e
```

The E2E test script verifies: TDX detection, RTMR[2] extension via container launch, quote generation and signature verification, and RTMR[2] consistency between the agent response and the quote.

### TDX hardware test (bare metal)

On a TDX-enabled host with QEMU, boot the custom mkosi image as a TD:

```bash
./scripts/run-td.sh

# From the host, after the TD boots:
# 1. Launch a workload
grpcurl -plaintext <vsock-proxy> attestation.agent.v1.AttestationAgent/LaunchContainer \
  -d '{"image_ref": "docker.io/library/nginx:latest"}'

# 2. Get a quote
grpcurl -plaintext <vsock-proxy> attestation.agent.v1.AttestationAgent/GetQuote \
  -d '{"report_data": "<base64-encoded-64-bytes>"}'

# 3. Verify the quote
./bin/verify-quote --quote quote.bin --policy policy.json
```

## Verification Policy

The `verify-quote` CLI checks a TDX quote against a JSON policy file listing approved measurement tuples:

```json
{
  "entries": [
    {
      "description": "base image v0.1.0 + nginx:1.27",
      "mrtd":  "hex...",
      "rtmr0": "hex...",
      "rtmr1": "hex...",
      "rtmr2": "hex..."
    }
  ]
}
```

Empty fields are wildcards (not checked). Compute reference values with:

```bash
./scripts/compute-reference.sh image/tdx-attestation-base.raw
```

## Measurement Flow

```
RTMR[2] = SHA384( zeros_48 || pad48(sha256(oci_manifest)) )
```

1. Agent pulls the OCI image via podman
2. Extracts the manifest digest (`sha256:...`)
3. Pads the 32-byte SHA-256 hash to 48 bytes (zero-padded right)
4. Extends RTMR[2] via configfs-tsm: `new_rtmr = SHA384(old_rtmr || padded_digest)`
5. Starts the container
6. A verifier computes the same value from the known manifest digest and compares against the quote
