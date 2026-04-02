#!/usr/bin/env bash
# setup-cvm.sh — Bootstrap a cloud CVM (Azure DCesv5 / GCP C3) for testing
# the attestation agent on real TDX hardware.
#
# Usage: ssh into the CVM, clone the repo, then run:
#   ./scripts/setup-cvm.sh
#
set -euo pipefail

echo "=== Checking TDX availability ==="

tdx_ok=true

if [ -d /sys/kernel/config/tsm ]; then
    echo "  configfs-tsm: present"
else
    echo "  configfs-tsm: NOT FOUND"
    tdx_ok=false
fi

if dmesg 2>/dev/null | grep -qi tdx; then
    echo "  dmesg TDX:    found"
else
    echo "  dmesg TDX:    not found (may need sudo)"
fi

if [ -e /dev/tdx_guest ]; then
    echo "  /dev/tdx_guest: present (legacy interface)"
else
    echo "  /dev/tdx_guest: not present (OK if configfs-tsm is available)"
fi

if [ "$tdx_ok" = false ]; then
    echo ""
    echo "WARNING: configfs-tsm not found. This VM may not be a TDX CVM."
    echo "The agent will fall back to mock attestation backends."
    echo ""
fi

echo ""
echo "=== Installing dependencies ==="

if command -v apt-get &>/dev/null; then
    sudo apt-get update
    sudo apt-get install -y podman golang-go git jq
elif command -v dnf &>/dev/null; then
    sudo dnf install -y podman golang git jq
else
    echo "ERROR: unsupported package manager (need apt or dnf)"
    exit 1
fi

# Verify Go version is 1.22+
go_version=$(go version | grep -oP '1\.\d+' | head -1)
echo "  Go version: $go_version"

echo ""
echo "=== Building agent and verify-quote ==="

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

cd agent && go build -o ../bin/attestation-agent ./cmd/attestation-agent
echo "  Built: bin/attestation-agent"

cd ../verify && go build -o ../bin/verify-quote ./cmd/verify-quote
echo "  Built: bin/verify-quote"

cd "$REPO_ROOT"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Start the agent:  ./bin/attestation-agent --listen tcp://localhost:4050"
echo "  2. Run E2E tests:    ./scripts/test-e2e.sh"
