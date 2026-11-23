#!/usr/bin/env bash
#
# thunderbridge çalıştırma scripti.
#
# Kullanım:
#   ./run.sh auth <proton-kullanıcı-adı>    # ilk kurulum / yeniden giriş (bir kez)
#   ./run.sh <proton-kullanıcı-adı>         # IMAP+SMTP sunucusunu TLS ile başlat
#
# İlk giriş sırasında Proton CAPTCHA isteyebilir. Gerekirse doğrulama sayfası açılır;
# yalnızca gözden geçirilmiş userscript token'ı nonce-korumalı yerel callback'e iletir.
# Callback çalışmazsa giriş iptal edilir; token terminale veya konsola yapıştırılmaz.

set -euo pipefail

# Script nerede olursa olsun proje köküne geç.
cd "$(dirname "$0")"

BIN=./target/release/thunderbridge

echo "[thunderbridge] release derleniyor..."
cargo build --release

# --- auth modu: ./run.sh auth <kullanıcı> ---
if [[ "${1:-}" == "auth" ]]; then
  USER="${2:-}"
  if [[ -z "$USER" ]]; then
    echo "kullanım: ./run.sh auth <proton-kullanıcı-adı>" >&2
    exit 1
  fi
  echo "[thunderbridge] giriş yapılıyor: $USER"
  exec "$BIN" auth "$USER"
fi

# --- serve modu: ./run.sh <kullanıcı> ---
USER="${1:-}"
if [[ -z "$USER" ]]; then
  echo "kullanım:" >&2
  echo "  ./run.sh auth <proton-kullanıcı-adı>   # ilk kez / yeniden giriş" >&2
  echo "  ./run.sh <proton-kullanıcı-adı>        # sunucuyu TLS ile başlat" >&2
  exit 1
fi

cat <<EOF
[thunderbridge] TLS ile başlatılıyor. Thunderbird ayarları:
  IMAP  (SSL/TLS only):       127.0.0.1:1993
  SMTP  (SSL/TLS only):       127.0.0.1:1465
  Parola: 'auth' çıktısındaki BRIDGE PASSWORD (Proton parolan değil).
Durdurmak için Ctrl+C.
EOF

exec "$BIN" serve "$USER" --tls
