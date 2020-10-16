#!/usr/bin/env sh

set -e

cd "$(dirname "$(which "$0")")/.." || return 1
./scripts/stat.py --wiitdb stuff/wiitdb.txt symbols/*.txt
