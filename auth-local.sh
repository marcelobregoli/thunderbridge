#!/usr/bin/env bash
# Local-only login helper. Passwords/OTP are entered through no-echo TTY prompts.
# The generated bridge password is sent directly to the Wayland clipboard and
# deliberately redacted from terminal output so it never enters chat/tool logs.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x ./target/release/thunderbridge ]]; then
  ./build.sh
fi
if ! command -v wl-copy >/dev/null 2>&1; then
  echo "wl-copy is required to keep the generated bridge password out of terminal output." >&2
  exit 1
fi

username="${1:-}"
if [[ -z "$username" ]]; then
  read -r -p "Proton username/address: " username
fi
if [[ -z "$username" ]]; then
  echo "No username entered." >&2
  exit 1
fi

./target/release/thunderbridge auth "$username" 2>&1 | awk '
  /Bridge password/ {
    print
    if (getline > 0) {
      secret = $0
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", secret)
      if (secret == "") {
        print "      [bridge password was not captured]"
        exit 1
      }
      printf "%s", secret | "wl-copy"
      copy_status = close("wl-copy")
      if (copy_status != 0) {
        print "      [clipboard copy failed]"
        exit 1
      }
      print "      [bridge password copied to clipboard; value hidden]"
    }
    next
  }
  { print }
'
