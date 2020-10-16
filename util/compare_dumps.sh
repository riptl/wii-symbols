#!/usr/bin/env bash

set -e

cd "$(dirname "$(which "$0")")/.." || return 1

for GAMEID in "$@"
do
    PAIRS+=("./stuff/dumps/$GAMEID.bin:./symbols/$GAMEID.txt")
done
./scripts/compare_dumps.py --base 0x80000000 "${PAIRS[@]}"
