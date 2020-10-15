#!/usr/bin/env sh

set -e

cd "$(dirname "$(which "$0")")/.." || return 1
find ./scripts -type f -name '*.py' -print0 | xargs -0 black --check
