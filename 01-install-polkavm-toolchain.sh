#!/usr/bin/env bash

set -euo pipefail

case "$OSTYPE" in
  linux*)
    if ! [[ "$(rustup toolchain list)" =~ "riscv32ema" ]]; then
        curl -L --output /tmp/toolchain.tar.zst  "https://github.com/paritytech/rustc-rv32e-toolchain/releases/download/v1.1.0/rust-rve-nightly-2024-01-05-x86_64-unknown-linux-gnu.tar.zst"
    fi
  ;;
  darwin*)
    arch="x86_64"
    if [[ "$(uname -m)" =~ "arm64" ]]; then
      arch="aarch64"
    fi

    if  ! [[ "$(rustup toolchain list)" =~ "riscv32ema" ]]; then
        curl -L --output /tmp/toolchain.tar.zst  "https://github.com/paritytech/rustc-rv32e-toolchain/releases/download/v1.1.0/rust-rve-nightly-2024-01-05-${arch}-apple-darwin.tar.zst"
    fi
  ;;
  *)
    echo "Unknown OS type: $OSTYPE"
    exit 1
  ;;
esac

tar --zstd -C /tmp -xf /tmp/toolchain.tar.zst
mkdir -p ~/.rustup/toolchains
mv /tmp/rve-nightly ~/.rustup/toolchains/riscv32ema
