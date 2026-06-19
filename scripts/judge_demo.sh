#!/usr/bin/env bash
# scripts/judge_demo.sh — judge POV end-to-end demo runner.
#
# What it does:
#   1. Builds `themis-orchestrator` in release mode.
#   2. Starts the HTTP server on an ephemeral port.
#   3. POSTs the canned `stark-001` fixture (cross-tenant double-spend,
#      risk_score 0.92) to /invoices.
#   4. Polls until the BAAAR HALT flow completes.
#   5. Downloads the Evidence Packet PDF from /packets/:id/pdf.
#   6. Copies the PDF to ~/Escritorio/apohara-vouch-judge-demo.pdf.
#   7. Also dumps the SealedPacket JSON next to it for vouch-verify.
#
# Usage:
#   ./scripts/judge_demo.sh
#
# Exit codes:
#   0 = PDF written to ~/Escritorio/
#   1 = build / server / POST / GET failure
#
# Cost: zero — uses the MockLlmProvider + ScriptedBandRoom (no
# FEATHERLESS_API_KEY or AIML_API_KEY needed). The fixture loader
# recognises `stark-001` and forces the fraud_auditor to emit the
# BAAAR HALT payload (the wow moment).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DESKTOP="$HOME/Escritorio"
PDF_OUT="$DESKTOP/apohara-vouch-judge-demo.pdf"
JSON_OUT="$DESKTOP/apohara-vouch-judge-demo.json"
LOG_OUT="$DESKTOP/apohara-vouch-judge-demo.log"
PORT="${JUDGE_PORT:-18080}"

mkdir -p "$DESKTOP"

echo "[judge-demo] building themis-orchestrator (release)..."
( cd "$REPO_ROOT" && cargo build --release --bin themis-orchestrator 2>&1 | tail -3 )

BIN="$REPO_ROOT/target/release/themis-orchestrator"
test -x "$BIN" || { echo "[judge-demo] binary not built: $BIN" >&2; exit 1; }

echo "[judge-demo] starting server on 127.0.0.1:$PORT ..."
( cd "$REPO_ROOT" && PORT="$PORT" "$BIN" >"$LOG_OUT" 2>&1 ) &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true' EXIT

# Wait for /health (or fall back to a short sleep).
for _ in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$PORT/fixtures" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

echo "[judge-demo] POST /invoices  tenant=stark  invoice=stark-001 ..."
POST_RESP=$(curl -sf -X POST "http://127.0.0.1:$PORT/invoices" \
    -H 'content-type: application/json' \
    -d '{"tenant_id":"stark","invoice_id":"stark-001","raw_b64":""}')
echo "[judge-demo] response: $POST_RESP"

PACKET_ID=$(echo "$POST_RESP" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("packet_id") or d.get("id") or "")')
test -n "$PACKET_ID" || { echo "[judge-demo] no packet_id in response" >&2; exit 1; }
echo "[judge-demo] packet_id=$PACKET_ID"

# Give the orchestrator a beat to flush the chain + sign.
sleep 1

echo "[judge-demo] GET /packets/$PACKET_ID/pdf ..."
curl -sf "http://127.0.0.1:$PORT/packets/$PACKET_ID/pdf" -o "$PDF_OUT"
test -s "$PDF_OUT" || { echo "[judge-demo] PDF is empty: $PDF_OUT" >&2; exit 1; }

echo "[judge-demo] GET /packets/$PACKET_ID/json ..."
curl -sf "http://127.0.0.1:$PORT/packets/$PACKET_ID/json" -o "$JSON_OUT"

echo ""
echo "============================================================"
echo "  Judge demo artifacts written:"
echo "    PDF : $PDF_OUT ($(stat -c %s "$PDF_OUT" 2>/dev/null || wc -c <"$PDF_OUT") bytes)"
echo "    JSON: $JSON_OUT ($(stat -c %s "$JSON_OUT" 2>/dev/null || wc -c <"$JSON_OUT") bytes)"
echo "    LOG : $LOG_OUT"
echo ""
echo "  Verify offline:"
echo "    cd $REPO_ROOT"
echo "    cargo run --release --bin vouch-verify -- $JSON_OUT"
echo ""
echo "  What the judge should see in the PDF:"
echo "    - Verdict pill: HALT (red)"
echo "    - Reason: 'risk_score_exceeded — cross-tenant double-spend'"
echo "    - 7/8 EU AI Act Art. 12 fields populated"
echo "    - QR code (48mm) bottom-right for offline vouch-verify"
echo "    - Ed25519 signature + BLAKE3 chain tip"
echo "============================================================"