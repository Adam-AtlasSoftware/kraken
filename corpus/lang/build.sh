#!/usr/bin/env bash
# Builds the corpus/lang programs with the host's rustc (no container; these are small and
# freestanding). Output: bin/<name>-<legacy|v0> with symbols and -stripped.
#   corpus/lang/build.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
mkdir -p bin
for mangling in legacy v0; do
  out="bin/rust_hello-$mangling"
  # legacy mangling is no longer stable; RUSTC_BOOTSTRAP lets the stable compiler write it
  RUSTC_BOOTSTRAP=1 rustc --edition 2024 --crate-type bin -C opt-level=1 -C panic=abort -C debuginfo=0 \
    -Z unstable-options -C symbol-mangling-version="$mangling" -C relocation-model=pic \
    -C link-arg=-lc -C strip=none src/rust_hello.rs -o "$out"
  strip -o "$out-stripped" "$out"
done
find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256
sha256sum src/* build.sh >> MANIFEST.sha256
