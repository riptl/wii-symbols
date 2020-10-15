#!/usr/bin/env sh

set -e

cd "$(dirname "$(which "$0")")/.." || return 1
find ./scripts -type f -name '*.py' -exec black {} +
