#!/usr/bin/env bash
# Integration test: publish a kind 5 (deletion request) targeting a
# non-existent event. Reproduces the bug where the relay returns
# "blocked: nothing to delete" instead of accepting the deletion request.
#
# Requires: nak, curl
# Usage: ./test/deletion_nothing_to_delete_test.sh

set -euo pipefail

PORT=33341
DATA_DIR=$(mktemp -d)
LOG_FILE=$(mktemp)
BINARY=$(mktemp -u)
RELAY_PID=""
URL="ws://localhost:${PORT}"

cleanup() {
    if [ -n "${RELAY_PID}" ]; then
        kill "${RELAY_PID}" 2>/dev/null || true
        wait "${RELAY_PID}" 2>/dev/null || true
    fi
    rm -rf "${DATA_DIR}" "${LOG_FILE}" "${BINARY}"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    echo "--- relay log ---" >&2
    cat "${LOG_FILE}" >&2
    exit 1
}

echo "==> Building relay binary"
go build -o "${BINARY}" ./cmd/relay

echo "==> Starting relay on port ${PORT} (data: ${DATA_DIR})"
RELAY_PORT=${PORT} RELAY_HOST=127.0.0.1 RELAY_DATA_PATH=${DATA_DIR} \
    "${BINARY}" >"${LOG_FILE}" 2>&1 &
RELAY_PID=$!

echo "==> Waiting for relay to be ready"
for _ in $(seq 1 50); do
    if curl -sf -H "Accept: application/nostr+json" "http://localhost:${PORT}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
curl -sf -H "Accept: application/nostr+json" "http://localhost:${PORT}" >/dev/null \
    || fail "relay did not start within 10s"

SK=$(nak key generate)

echo "==> Publishing kind 5 deletion request for non-existent event"
OUTPUT=$(nak event -k 5 \
    -t e=0000000000000000000000000000000000000000000000000000000000000000 \
    --sec "${SK}" "${URL}" 2>&1) \
    || true

echo "${OUTPUT}"

if echo "${OUTPUT}" | grep -q "failed.*nothing to delete"; then
    fail "relay rejected kind 5 with 'nothing to delete' — it should accept the deletion request"
fi

if ! echo "${OUTPUT}" | grep -q "success"; then
    fail "relay did not accept the kind 5 deletion request"
fi

echo "PASS: kind 5 deletion request for non-existent event is accepted"
