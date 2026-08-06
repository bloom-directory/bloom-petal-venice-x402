#!/usr/bin/env bash
# Build the route components into a Petal package tree and run the same gate
# CI uses. `cargo test` alone does NOT compile the route files (each is built
# as its own crate by the petal builder), so this is the only check that
# catches route-file compile errors and a stale petal-build.toml.
#
# Prerequisites: rust toolchain (stable), the `wasm32-unknown-unknown` target,
# `wasm-tools`, and the `petal` CLI (https://github.com/bloom-directory/petal).
set -euo pipefail

if ! command -v petal >/dev/null 2>&1; then
  echo "error: 'petal' CLI not found. Install with:" >&2
  echo "  cargo install --git https://github.com/bloom-directory/petal bloom-petal-cli" >&2
  exit 1
fi
if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "error: 'wasm-tools' not found. Install with: cargo install wasm-tools --locked" >&2
  exit 1
fi

petal build
