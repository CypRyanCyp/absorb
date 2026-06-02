#!/usr/bin/env bash
# Builds the debug APK (requires Google Maven access) and installs it on the
# emulator (or any connected ADB device/emulator).
# Usage: ./scripts/install-debug.sh [adb-serial]
# Example: ./scripts/install-debug.sh 127.0.0.1:5555

set -euo pipefail

SERIAL=${1:-"127.0.0.1:5555"}
FLUTTER=${FLUTTER_ROOT:-"$(dirname "$0")/../../flutter"}/bin/flutter
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_ID="com.barnabas.absorb"

cd "$REPO_ROOT"

echo "Building debug APK…"
"$FLUTTER" build apk --debug

APK=$(find build -name "*.apk" -path "*/debug/*" | head -1)
if [[ -z "$APK" ]]; then
  echo "ERROR: APK not found after build" >&2; exit 1
fi

echo "Installing $APK on $SERIAL…"
adb -s "$SERIAL" install -r "$APK"
echo "Launching app…"
adb -s "$SERIAL" shell am start -n "${APP_ID}/${APP_ID}.MainActivity"
echo "Done. Run scripts/logcat-mtls.sh to monitor mTLS logs."
