#!/usr/bin/env bash
# test-e2e.sh — End-to-end test of the attestation agent on TDX hardware.
#
# Prerequisites:
#   - Agent running: sudo ./bin/attestation-agent --listen tcp://localhost:4050
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
OUTDIR="$PWD/test-e2e-out"
mkdir -p "$OUTDIR"

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

# Helper: get a quote and extract raw bytes + RTMR[2].
# Usage: get_quote <output-bin-path>
# Sets: $last_quote_rtmr2 (hex)
last_quote_rtmr2=""
get_quote() {
    local out_path="$1"
    local rd_b64
    rd_b64=$(head -c 64 /dev/urandom | base64 | tr -d '\n')
    local qj
    qj=$(grpcurl -plaintext -d "{\"report_data\": \"$rd_b64\"}" \
        "$AGENT_ADDR" attestation.agent.v1.AttestationAgent/GetQuote 2>&1) || return 1
    local qb64
    qb64=$(echo "$qj" | jq -r '.quote // empty')
    [ -n "$qb64" ] || return 1
    echo -n "$qb64" | base64 -d > "$out_path"

    # Parse RTMR[2] from the quote via verify-quote (wildcard policy).
    local wildcard="$OUTDIR/_wildcard.json"
    cat > "$wildcard" <<'WC'
{"entries":[{"description":"wildcard","mrtd":"","rtmr0":"","rtmr1":"","rtmr2":""}]}
WC
    local vout
    vout=$("$REPO_ROOT/bin/verify-quote" --quote "$out_path" --policy "$wildcard" 2>&1) || return 1
    last_quote_rtmr2=$(echo "$vout" | grep 'RTMR\[2\]' | awk '{print $2}')
}

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

# ---------- Test 2: Baseline quote (pre-launch RTMR[2]) ----------
echo "--- Test 2: Baseline quote ---"
rtmr2_pre=""
if get_quote "$OUTDIR/quote-baseline.bin"; then
    rtmr2_pre="$last_quote_rtmr2"
    ok "baseline RTMR[2]: $rtmr2_pre"
else
    err "failed to get baseline quote"
fi

echo ""

# ---------- Test 3: LaunchContainer ----------
echo "--- Test 3: LaunchContainer ---"
workload_measurement=""
launch_json=$(grpcurl -plaintext -d '{
  "image_ref": "docker.io/library/alpine:latest",
  "command": ["echo", "hello from measured container"]
}' "$AGENT_ADDR" attestation.agent.v1.AttestationAgent/LaunchContainer 2>&1) || {
    err "LaunchContainer RPC failed"
    echo "  Output: $launch_json"
    echo ""
    launch_json=""
}

if [ -n "$launch_json" ]; then
    container_id=$(echo "$launch_json" | jq -r '.containerId // empty')
    manifest_digest=$(echo "$launch_json" | jq -r '.manifestDigest // empty')
    workload_measurement=$(echo "$launch_json" | jq -r '.workloadMeasurement // empty')

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

    if [ -n "$workload_measurement" ]; then
        ok "workload measurement: ${workload_measurement:0:32}..."
    else
        err "no workload_measurement in response"
    fi
fi

echo ""

# ---------- Test 4: Post-launch quote ----------
echo "--- Test 4: Post-launch quote ---"
rtmr2_post=""
if get_quote "$OUTDIR/quote.bin"; then
    rtmr2_post="$last_quote_rtmr2"
    ok "post-launch RTMR[2]: ${rtmr2_post:0:32}..."
else
    err "failed to get post-launch quote"
fi

echo ""

# ---------- Test 5: Verify quote signature + RTMR[2] computation ----------
echo "--- Test 5: Quote verification ---"
if [ -f "$OUTDIR/quote.bin" ]; then
    policy_file="$OUTDIR/policy.json"
    cat > "$policy_file" <<POLICY
{
  "entries": [
    {
      "description": "cloud CVM - all wildcards (signature and format check only)",
      "mrtd":  "",
      "rtmr0": "",
      "rtmr1": "",
      "rtmr2": ""
    }
  ]
}
POLICY

    # Build verify-quote flags: if we have baseline RTMR[2] and workload
    # measurement, pass them so verify-quote can check the RTMR[2] transition.
    verify_flags=()
    if [ -n "$rtmr2_pre" ] && [ -n "$workload_measurement" ]; then
        verify_flags+=(--rtmr2-pre "$rtmr2_pre" --measurement "$workload_measurement")
    fi

    verify_out=$("$REPO_ROOT/bin/verify-quote" --quote "$OUTDIR/quote.bin" --policy "$policy_file" "${verify_flags[@]}" 2>&1) || {
        err "verify-quote failed"
        echo "  Output: $verify_out"
        verify_out=""
    }

    if [ -n "$verify_out" ]; then
        if echo "$verify_out" | grep -q "policy check: PASSED"; then
            ok "quote signature and policy check passed"
        else
            err "policy check did not pass"
        fi

        if echo "$verify_out" | grep -q "RTMR\[2\] verification: PASSED"; then
            ok "RTMR[2] = SHA384(rtmr2_pre || workload_measurement) — verified"
        elif [ -n "$rtmr2_pre" ] && [ -n "$workload_measurement" ]; then
            err "RTMR[2] computation mismatch"
        fi

        # Print measurements.
        echo "$verify_out" | grep -E "^(MRTD|RTMR|quote|  )" | sed 's/^/  /'
    fi
else
    echo "  SKIP: no quote file"
fi

echo ""

# ---------- Test 6: RTMR[2] changed after extension ----------
echo "--- Test 6: RTMR[2] pre vs post ---"
if [ -n "$rtmr2_pre" ] && [ -n "$rtmr2_post" ]; then
    if [ "$rtmr2_pre" != "$rtmr2_post" ]; then
        ok "RTMR[2] changed after LaunchContainer"
    else
        err "RTMR[2] did not change — extension may have failed"
    fi
else
    echo "  SKIP: missing pre or post RTMR[2]"
fi

echo ""
echo "==============================="
echo "RESULT: $pass passed, $fail failed"
echo "==============================="

[ "$fail" -eq 0 ]
