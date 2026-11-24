#!/usr/bin/env bash
# Reproducible local build for Fedora/Linux with Proton's Go-backed GopenPGP.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.26 or newer is required to build Proton GopenPGP." >&2
  exit 1
fi
GO_VERSION="$(go env GOVERSION | sed 's/^go//')"
GO_MAJOR="${GO_VERSION%%.*}"
GO_MINOR="${GO_VERSION#*.}"
GO_MINOR="${GO_MINOR%%.*}"
if (( GO_MAJOR < 1 || (GO_MAJOR == 1 && GO_MINOR < 26) )); then
  echo "Go 1.26 or newer is required; found $GO_VERSION." >&2
  exit 1
fi

# Bindgen needs libclang and Clang's resource headers. Fedora installs them
# separately; detect the newest available versions without hard-coding 22.
if [[ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]]; then
  CLANG_RESOURCE_INCLUDE="$(find /usr/lib/clang -mindepth 3 -maxdepth 3 -type f -name stddef.h -printf '%h\n' 2>/dev/null | sort -V | tail -n 1)"
  if [[ -z "$CLANG_RESOURCE_INCLUDE" ]]; then
    echo "Clang resource headers were not found. Install the Fedora clang-libs package or set BINDGEN_EXTRA_CLANG_ARGS." >&2
    exit 1
  fi
  export BINDGEN_EXTRA_CLANG_ARGS="-isystem $CLANG_RESOURCE_INCLUDE"
fi
if [[ -z "${LIBCLANG_PATH:-}" ]]; then
  LIBCLANG_SO="$(find /usr/lib64/llvm* -type f -name 'libclang.so.*' -print 2>/dev/null | sort -V | tail -n 1)"
  if [[ -z "$LIBCLANG_SO" ]]; then
    echo "libclang was not found. Install the Fedora llvm-libs/clang-libs packages or set LIBCLANG_PATH." >&2
    exit 1
  fi
  export LIBCLANG_PATH="$(dirname "$LIBCLANG_SO")"
fi

echo "[thunderbridge] Building with Go $GO_VERSION and locked Rust dependencies..."
cargo build --release --locked
