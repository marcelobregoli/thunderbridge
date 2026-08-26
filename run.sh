#!/usr/bin/env bash
#
# thunderbridge çalıştırma scripti.
#
# Kullanım:
#   ./run.sh auth <proton-kullanıcı-adı>    # ilk kurulum / yeniden giriş (bir kez)
#   ./run.sh <proton-kullanıcı-adı>         # IMAP+SMTP sunucusunu TLS ile başlat
#
# İlk giriş sırasında Proton "human verification" (CAPTCHA) isteyebilir; tarayıcıda
# verify.proton.me açılır. Ya userscript'i (tools/proton-hv-capture.user.js) kur, ya da
# aşağıdaki konsol JS'ini kullan; token'ı otomatik gönderemezse çözülen token'ı
# terminaldeki "> " istemine yapıştır.

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
  IMAP  (STARTTLS yok, düz):  127.0.0.1:1143
  IMAPS (SSL/TLS):            127.0.0.1:1993
  SMTP  (düz):                127.0.0.1:1025
  SMTPS (SSL/TLS):            127.0.0.1:1465
  Parola: 'auth' çıktısındaki BRIDGE PASSWORD (Proton parolan değil).
Durdurmak için Ctrl+C.
EOF

exec "$BIN" serve "$USER" --tls
