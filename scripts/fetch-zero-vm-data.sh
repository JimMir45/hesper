#!/usr/bin/env bash
# Fetch offline detection-chain data for the zero-vm profile:
#   1. chainsaw static binary (latest release, linux-musl)
#   2. SigmaHQ/sigma rules (shallow clone)
#   3. chainsaw sigma-event-logs-all mapping file
#   4. sbousseaden/EVTX-ATTACK-SAMPLES (shallow clone)
# Everything lands under lab/state/ (git-ignored). Idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p lab/state/bin lab/state/sigma-mappings lab/state/chainsaw-out

# 1. chainsaw binary (x86_64 gnu build — repo moved to WithSecureOpenSource,
#    and v2.18+ ships no musl build, so the zero-vm container is debian)
if [ ! -x lab/state/bin/chainsaw ]; then
  url=$(curl -sfL https://api.github.com/repos/WithSecureOpenSource/chainsaw/releases/latest \
    | grep -oE '"browser_download_url": *"[^"]*x86_64-unknown-linux-gnu\.tar\.gz"' | head -1 | cut -d'"' -f4)
  [ -n "$url" ] || { echo "ERROR: cannot resolve chainsaw linux-gnu release URL"; exit 1; }
  echo "fetching $url"
  curl -sfL "$url" -o /tmp/chainsaw.tar.gz
  rm -rf /tmp/chainsaw-bin && mkdir -p /tmp/chainsaw-bin
  tar -xzf /tmp/chainsaw.tar.gz -C /tmp/chainsaw-bin
  cp /tmp/chainsaw-bin/*/chainsaw lab/state/bin/chainsaw 2>/dev/null || cp /tmp/chainsaw-bin/chainsaw lab/state/bin/chainsaw
  chmod +x lab/state/bin/chainsaw
fi
lab/state/bin/chainsaw --version

# 2. sigma rules
if [ ! -d lab/state/sigma/.git ]; then
  echo "cloning SigmaHQ/sigma (shallow)"
  git clone --depth 1 https://github.com/SigmaHQ/sigma.git lab/state/sigma
fi

# 3. sigma mapping from the chainsaw repo
if [ ! -f lab/state/sigma-mappings/sigma-event-logs-all.yml ]; then
  echo "fetching chainsaw sigma mapping"
  rm -rf /tmp/chainsaw-src
  git clone --depth 1 https://github.com/WithSecureOpenSource/chainsaw.git /tmp/chainsaw-src
  cp /tmp/chainsaw-src/mappings/sigma-event-logs-all.yml lab/state/sigma-mappings/
fi

# 4. EVTX attack samples
if [ ! -d lab/state/evtx-samples/.git ]; then
  echo "cloning EVTX-ATTACK-SAMPLES (shallow)"
  git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git lab/state/evtx-samples
fi

echo "zero-vm data ready under lab/state/"
