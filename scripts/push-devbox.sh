#!/usr/bin/env bash
# Sync the local hesper working tree to the devbox WSL workspace.
# Local authoring -> devbox execution (GitHub remains the source of truth;
# this script is for tight edit-verify loops, not for shipping).
#
# Usage (from repo root or anywhere):
#   bash scripts/push-devbox.sh            # sync + run dev.sh remotely
#   bash scripts/push-devbox.sh --no-test  # sync only
set -euo pipefail
cd "$(dirname "$0")/.."

REMOTE_DIR="\$HOME/hesper"
RUN_TESTS="${1:-}"

echo "== push-devbox: tar-over-ssh sync =="
tar czf - \
  --exclude='.git' \
  --exclude='lab/state' \
  --exclude='lab/artifacts' \
  --exclude='runs' \
  --exclude='node_modules' \
  --exclude='*.iso' \
  --exclude='.playwright-mcp' \
  . | ssh devbox "wsl -e bash -c 'mkdir -p $REMOTE_DIR && tar xzf - -C $REMOTE_DIR && echo SYNC-OK'"

if [ "$RUN_TESTS" != "--no-test" ]; then
  echo "== remote dev.sh =="
  ssh devbox "wsl -e bash -c 'cd $REMOTE_DIR && bash scripts/dev.sh'"
fi
