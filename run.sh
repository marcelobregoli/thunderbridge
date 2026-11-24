#!/usr/bin/env bash
#
# Usage:
#   ./run.sh auth <proton-username>    # first login / re-authentication
#   ./run.sh <proton-username>         # start TLS IMAP+SMTP servers
#
# Authentication may open Proton's CAPTCHA page. The reviewed userscript
# forwards the token only to the nonce-protected local callback.

set -euo pipefail
cd "$(dirname "$0")"

BIN=./target/release/thunderbridge
./build.sh

if [[ "${1:-}" == "auth" ]]; then
  USER="${2:-}"
  if [[ -z "$USER" ]]; then
    echo "Usage: ./run.sh auth <proton-username>" >&2
    exit 1
  fi
  exec ./auth-local.sh "$USER"
fi

USER="${1:-}"
if [[ -z "$USER" ]]; then
  echo "Usage:" >&2
  echo "  ./run.sh auth <proton-username>    # first login / re-authentication" >&2
  echo "  ./run.sh <proton-username>         # serve over TLS" >&2
  exit 1
fi

cat <<EOF2
[thunderbridge] Starting TLS-only local servers:
  IMAP: 127.0.0.1:1993 (SSL/TLS)
  SMTP: 127.0.0.1:1465 (SSL/TLS)
  Password: the BRIDGE PASSWORD copied to clipboard by auth-local.sh, not your Proton password.
Stop with Ctrl+C.
EOF2

exec "$BIN" serve "$USER" --tls
