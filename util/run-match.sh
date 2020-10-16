#!/usr/bin/env sh

set -e

cd "$(dirname "$(which "$0")")/.." || return 1
OUT_PATH="stuff/results/$1-$(date "+%y%m%d-%H%M%S").txt"
find ./stuff/libs -type f -name '*.a' -print0 | xargs -0 ./scripts/match_symbols.py -o "$OUT_PATH" "stuff/dumps/$1.bin"
sort -u -o "$OUT_PATH" "$OUT_PATH"
