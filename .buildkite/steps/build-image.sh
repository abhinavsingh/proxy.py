#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.8.12-testnet}
set ${EVM_LOADER_REVISION:=latest}

# Refreshing neonlabsorg/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/solana:${SOLANA_REVISION}

# Refreshing neonlabsorg/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/evm_loader:${EVM_LOADER_REVISION}

docker build -t neonlabsorg/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    --build-arg PROXY_REVISION=${REVISION} \
    .
