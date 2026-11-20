#!/usr/bin/env bash
# Hesper dev loop — run inside WSL from anywhere:
#   wsl -e bash /mnt/c/Users/jiang/orca/projects/hesper/scripts/dev.sh
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== go build =="
go build ./...
echo "== go vet =="
go vet ./...
echo "== go test =="
go test ./...
echo "BUILD-OK VET-OK TEST-OK"
