#!/bin/bash
set -euo pipefail

# Compute expected MRTD and RTMR reference values from a built image.
# These values are used to populate the verification policy file.
#
# Usage: ./scripts/compute-reference.sh [path-to-disk-image]
#
# Requires: measured-boot-tools (https://github.com/intel/measured-boot-tools)

IMAGE="${1:-image/tdx-attestation-base.raw}"

if [ ! -f "$IMAGE" ]; then
    echo "Error: disk image not found at $IMAGE"
    echo "Build it first with: make image"
    exit 1
fi

echo "=== Computing reference measurements for: $IMAGE ==="
echo ""

# Extract UKI from the ESP partition.
echo "--- Extracting UKI from ESP ---"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Mount ESP (first partition) — requires root.
LOOPDEV=$(sudo losetup --find --show --partscan "$IMAGE")
sudo mount "${LOOPDEV}p1" "$TMPDIR"

UKI=$(find "$TMPDIR" -name '*.efi' -path '*/EFI/Linux/*' | head -1)
if [ -z "$UKI" ]; then
    echo "Error: no UKI found in ESP"
    sudo umount "$TMPDIR"
    sudo losetup -d "$LOOPDEV"
    exit 1
fi
echo "Found UKI: $UKI"

# Compute MRTD (firmware measurement).
echo ""
echo "--- MRTD (firmware measurement) ---"
echo "MRTD must be computed from the TDVF binary used to build the image."
echo "Use: measured-boot-tools mrtd --firmware /path/to/OVMF_CODE.fd"

# Compute RTMR[1] (UKI measurement — kernel + initrd + cmdline).
echo ""
echo "--- RTMR[1] (UKI = kernel + initrd + cmdline + verity root hash) ---"
echo "Compute with: measured-boot-tools rtmr --uki $UKI"

# Compute expected RTMR[2] for a given workload image.
echo ""
echo "--- RTMR[2] (workload measurement) ---"
echo "For a given OCI image digest sha256:XXXX, compute:"
echo "  1. Pad the 32-byte SHA-256 digest to 48 bytes (zero-pad right)"
echo "  2. RTMR[2] = SHA384(zeros_48 || padded_digest)"
echo ""
echo "Example with the verify-quote tool:"
echo "  verify-quote --compute-rtmr2 sha256:<manifest-digest>"

sudo umount "$TMPDIR"
sudo losetup -d "$LOOPDEV"
