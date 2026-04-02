#!/usr/bin/env bash
# test-e2e.sh — End-to-end test of the attestation agent on TDX hardware.
#
# Prerequisites:
#   - Agent running: ./bin/attestation-agent --listen tcp://localhost:4050
#   - grpcurl installed (or go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
#   - jq installed
#   - podman available (for container launch test)
#
# Usage:
#   ./scripts/test-e2e.sh [agent-address]
#   Default agent address: localhost:4050
#
set -euo pipefail

AGENT_ADDR="${1:-localhost:4050}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pass=0
fail=0

ok() {
    echo "  PASS: $1"
    pass=$((pass + 1))
}

err() {
    echo "  FAIL: $1"
    fail=$((fail + 1))
}

# Ensure grpcurl is available.
if ! command -v grpcurl &>/dev/null; then
    echo "Installing grpcurl..."
    go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
    export PATH="$PATH:$(go env GOPATH)/bin"
fi

echo "=== E2E Test Suite ==="
echo "Agent address: $AGENT_ADDR"
echo ""

# ---------- Test 1: GetStatus ----------
echo "--- Test 1: GetStatus ---"
status_json=$(grpcurl -plaintext "$AGENT_ADDR" attestation.agent.v1.AttestationAgent/GetStatus 2>&1) || {
    err "GetStatus RPC failed (is the agent running?)"
    echo "  Output: $status_json"
    echo ""
    echo "RESULT: 0 passed, 1 failed (agent not reachable)"
    exit 1
}

ready=$(echo "$status_json" | jq -r '.ready')
tdx=$(echo "$status_json" | jq -r '.tdxAvailable')

if [ "$ready" = "true" ]; then
    ok "agent is ready"
else
    err "agent not ready"
fi

if [ "$tdx" = "true" ]; then
    ok "TDX hardware detected"
else
    echo "  WARN: TDX not available — agent is using mock backends"
    echo "        (RTMR extension and quote generation will be simulated)"
fi

echo ""

# ---------- Test 2: LaunchContainer ----------
echo "--- Test 2: LaunchContainer ---"
launch_json=$(grpcurl -plaintext -d '{
  "image_ref": "docker.io/library/alpine:latest",
  "command": ["echo", "hello from measured container"]
}' "$AGENT_ADDR" attestation.agent.v1.AttestationAgent/LaunchContainer 2>&1) || {
    err "LaunchContainer RPC failed"
    echo "  Output: $launch_json"
    echo ""
    # Continue with remaining tests.
    launch_json=""
}

if [ -n "$launch_json" ]; then
    container_id=$(echo "$launch_json" | jq -r '.containerId // empty')
    manifest_digest=$(echo "$launch_json" | jq -r '.manifestDigest // empty')
    rtmr2_hex=$(echo "$launch_json" | jq -r '.rtmr2Value // empty')

    if [ -n "$container_id" ]; then
        ok "container launched: $container_id"
    else
        err "no container_id in response"
    fi

    if [ -n "$manifest_digest" ]; then
        ok "manifest digest: $manifest_digest"
    else
        err "no manifest_digest in response"
    fi

    if [ -n "$rtmr2_hex" ]; then
        ok "RTMR[2] extended: ${rtmr2_hex:0:32}..."
    else
        err "no rtmr2_value in response"
    fi
fi

echo ""

# ---------- Test 3: GetQuote ----------
echo "--- Test 3: GetQuote ---"
# Generate 64 bytes of random report data.
report_data_b64=$(head -c 64 /dev/urandom | base64 | tr -d '\n')

quote_json=$(grpcurl -plaintext -d "{\"report_data\": \"$report_data_b64\"}" \
    "$AGENT_ADDR" attestation.agent.v1.AttestationAgent/GetQuote 2>&1) || {
    err "GetQuote RPC failed"
    echo "  Output: $quote_json"
    quote_json=""
}

if [ -n "$quote_json" ]; then
    # Extract quote bytes (base64-encoded in grpcurl JSON output).
    quote_b64=$(echo "$quote_json" | jq -r '.quote // empty')

    if [ -n "$quote_b64" ]; then
        ok "quote generated ($(echo -n "$quote_b64" | wc -c | tr -d ' ') base64 chars)"

        # Decode and save raw quote for verify-quote.
        echo -n "$quote_b64" | base64 -d > "$TMPDIR/quote.bin"
        ok "quote saved to $TMPDIR/quote.bin ($(wc -c < "$TMPDIR/quote.bin" | tr -d ' ') bytes)"
    else
        err "no quote in response"
    fi

    # Check for certificate chain.
    cert_chain=$(echo "$quote_json" | jq -r '.certChain // empty')
    if [ -n "$cert_chain" ]; then
        ok "certificate chain present"
    else
        echo "  INFO: no certificate chain (expected on some platforms)"
    fi
fi

echo ""

# ---------- Test 4: Verify quote ----------
echo "--- Test 4: Quote verification ---"
if [ -f "$TMPDIR/quote.bin" ]; then
    # Use a wildcard policy for cloud CVM testing (we don't control Stage 1 measurements).
    # Only check RTMR[2] if we have it from LaunchContainer.
    policy_file="$TMPDIR/policy.json"

    if [ -n "${rtmr2_hex:-}" ]; then
        cat > "$policy_file" <<POLICY
{
  "entries": [
    {
      "description": "cloud CVM - wildcard stage 1, verify RTMR[2] only",
      "mrtd":  "",
      "rtmr0": "",
      "rtmr1": "",
      "rtmr2": "$rtmr2_hex"
    }
  ]
}
POLICY
    else
        cat > "$policy_file" <<POLICY
{
  "entries": [
    {
      "description": "cloud CVM - all wildcards (signature check only)",
      "mrtd":  "",
      "rtmr0": "",
      "rtmr1": "",
      "rtmr2": ""
    }
  ]
}
POLICY
    fi

    verify_out=$("$REPO_ROOT/bin/verify-quote" --quote "$TMPDIR/quote.bin" --policy "$policy_file" 2>&1) || {
        err "verify-quote failed"
        echo "  Output: $verify_out"
        verify_out=""
    }

    if [ -n "$verify_out" ]; then
        if echo "$verify_out" | grep -q "policy check: PASSED"; then
            ok "quote verification and policy check passed"
        else
            err "policy check did not pass"
        fi
        # Print the measurements for inspection.
        echo "$verify_out" | grep -E "^(MRTD|RTMR|quote)" | sed 's/^/  /'
    fi
else
    echo "  SKIP: no quote file (GetQuote failed)"
fi

echo ""

# ---------- Test 5: RTMR[2] consistency check ----------
echo "--- Test 5: RTMR[2] consistency ---"
if [ -n "${manifest_digest:-}" ] && [ -n "${verify_out:-}" ]; then
    # Extract RTMR[2] from the quote (as printed by verify-quote).
    quote_rtmr2=$(echo "$verify_out" | grep 'RTMR\[2\]' | awk '{print $2}')

    if [ -n "$quote_rtmr2" ] && [ -n "${rtmr2_hex:-}" ]; then
        if [ "$quote_rtmr2" = "$rtmr2_hex" ]; then
            ok "RTMR[2] in quote matches LaunchContainer response"
        else
            err "RTMR[2] mismatch: quote=$quote_rtmr2 vs launch=$rtmr2_hex"
        fi
    else
        echo "  SKIP: could not extract RTMR[2] for comparison"
    fi
else
    echo "  SKIP: missing manifest_digest or verify output"
fi

echo ""
echo "==============================="
echo "RESULT: $pass passed, $fail failed"
echo "==============================="

[ "$fail" -eq 0 ]
