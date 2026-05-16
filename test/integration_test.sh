#!/usr/bin/env bash
# Integration test: publish an addressable event (kind 30817 — the kind used
# for NIP drafts) to the relay, then query it back. Reproduces the bug where
# non-regular events were silently dropped.
#
# Requires: nak, jq, curl
# Usage: ./test/integration_test.sh

set -euo pipefail

PORT=33340
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
PK=$(nak key public "${SK}")
DTAG="integration-test-$$"

echo "==> Publishing kind 30817 event (pubkey: ${PK:0:16}..., d: ${DTAG})"
nak event -k 30817 -d "${DTAG}" -c "integration test body" --sec "${SK}" "${URL}" \
    >/dev/null 2>&1 \
    || fail "nak event publish errored"

echo "==> Querying it back"
RESULT=$(nak req -k 30817 -a "${PK}" "${URL}" 2>/dev/null | head -1)

if [ -z "${RESULT}" ]; then
    fail "no event returned — addressable event was silently dropped by the relay"
fi

KIND=$(echo "${RESULT}" | jq -r .kind)
GOT_PK=$(echo "${RESULT}" | jq -r .pubkey)
GOT_D=$(echo "${RESULT}" | jq -r '.tags[] | select(.[0]=="d") | .[1]')

[ "${KIND}" = "30817" ] || fail "expected kind 30817, got '${KIND}'"
[ "${GOT_PK}" = "${PK}" ] || fail "expected pubkey ${PK}, got '${GOT_PK}'"
[ "${GOT_D}" = "${DTAG}" ] || fail "expected d-tag '${DTAG}', got '${GOT_D}'"

echo "PASS: addressable event round-trip works"
