#!/usr/bin/env bash

set -euo pipefail

export CARGO_TARGET_DIR="$(pwd)/target/riscv-guest"

cd zkevm-demo/methods/guest

RUSTFLAGS="-C target-feature=+lui-addi-fusion,+fast-unaligned-access -C relocation-model=pie -C link-arg=--emit-relocs -C link-arg=--unique" \
rustup run riscv32ema cargo build --release --target=riscv32ema-unknown-none-elf
