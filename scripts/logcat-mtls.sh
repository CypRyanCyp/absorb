#!/usr/bin/env bash
# Stream logcat filtered to mTLS, TLS, and just_audio tags.
# Usage: ./scripts/logcat-mtls.sh [adb-serial]

set -euo pipefail

SERIAL=${1:-"127.0.0.1:5555"}

adb -s "$SERIAL" logcat -c  # clear log buffer

echo "=== mTLS debug log (Ctrl-C to stop) ==="
adb -s "$SERIAL" logcat \
  MtlsHelper:V \
  just_audio:V \
  flutter:V \
  ExoPlayerImpl:V \
  DefaultHttpDataSource:V \
  SSLSocketFactory:V \
  SSLContext:V \
  '*:S' \
  2>/dev/null | grep --line-buffered -iE \
    "mtls|ssl|tls|certificate|handshake|just_audio|flutterError|p12|pkcs|trust|keystore|auth|403|401|javax\.net|SSLException|CertificateException"
