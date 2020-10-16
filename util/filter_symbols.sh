#!/usr/bin/env sh

set -e

cd "$(dirname "$(which "$0")")/.." || return 1
MATCH=$(ls -1t ./stuff/results/"$1"-*.txt | tail -n1)
echo "$MATCH"
./scripts/filter_symbols.py "$MATCH" -o "symbols/$1.txt"
