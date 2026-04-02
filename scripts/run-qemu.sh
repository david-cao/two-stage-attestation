#!/bin/bash
set -euo pipefail

# Boot the attestation base image in plain QEMU (no TDX) for development.
# Usage: ./scripts/run-qemu.sh [path-to-disk-image]

IMAGE="${1:-image/tdx-attestation-base.raw}"

if [ ! -f "$IMAGE" ]; then
    echo "Error: disk image not found at $IMAGE"
    echo "Build it first with: make image"
    exit 1
fi

OVMF="/usr/share/edk2/ovmf/OVMF_CODE.fd"
OVMF_VARS="/usr/share/edk2/ovmf/OVMF_VARS.fd"

# Create a temporary copy of OVMF_VARS so we don't modify the original.
TMPVARS=$(mktemp)
cp "$OVMF_VARS" "$TMPVARS"
trap "rm -f $TMPVARS" EXIT

exec qemu-system-x86_64 \
    -machine q35,accel=kvm \
    -cpu host \
    -m 2G \
    -smp 2 \
    -nographic \
    -drive "if=pflash,format=raw,readonly=on,file=$OVMF" \
    -drive "if=pflash,format=raw,file=$TMPVARS" \
    -drive "if=virtio,format=raw,file=$IMAGE" \
    -device "vhost-vsock-pci,guest-cid=3" \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0
