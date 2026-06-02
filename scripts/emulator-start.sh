#!/usr/bin/env bash
# Starts the docker-android emulator, waits for boot, and connects ADB.
# Run this on a machine with KVM and Docker available.
# Usage: ./scripts/emulator-start.sh [api-level]
# Default API level: 33

set -euo pipefail

API=${1:-33}
CONTAINER_NAME="absorb-emulator"
ADB_PORT=5555

# Check prerequisites
if ! command -v docker &>/dev/null; then
  echo "ERROR: docker not found" >&2; exit 1
fi
if [[ ! -e /dev/kvm ]]; then
  echo "ERROR: /dev/kvm not available — KVM required for hardware acceleration" >&2; exit 1
fi
if ! command -v adb &>/dev/null; then
  echo "ERROR: adb not found — install android-tools-adb" >&2; exit 1
fi

# Stop any existing instance
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

echo "Starting docker-android (API $API)…"
docker run -d \
  --name "$CONTAINER_NAME" \
  --device /dev/kvm \
  -p "${ADB_PORT}:5555" \
  -e MEMORY=4096 \
  -e CORES=4 \
  -e SKIP_AUTH=true \
  -e DISABLE_ANIMATION=true \
  "halimqarroum/docker-android:api-${API}"

echo "Waiting for emulator to boot (this takes ~60–90s)…"
# Poll adb until boot_completed
for i in $(seq 1 90); do
  sleep 2
  adb connect "127.0.0.1:${ADB_PORT}" &>/dev/null || true
  BOOT=$(adb -s "127.0.0.1:${ADB_PORT}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [[ "$BOOT" == "1" ]]; then
    echo "Emulator ready — connected as 127.0.0.1:${ADB_PORT}"
    adb devices
    exit 0
  fi
  printf "."
done

echo ""
echo "ERROR: Emulator did not boot within timeout. Check: docker logs $CONTAINER_NAME" >&2
exit 1
