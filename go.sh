#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULES=("gami-core" "gami-cli" "gami-api")

for module in "${MODULES[@]}"; do
    echo "==> $module: go $*"
    (cd "$SCRIPT_DIR/$module" && go "$@")
done
