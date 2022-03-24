#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.9.12-testnet}
set ${NEON_EVM_COMMIT:=latest}

# Refreshing neonlabsorg/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/solana:${SOLANA_REVISION}

# Refreshing neonlabsorg/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/evm_loader:${NEON_EVM_COMMIT}

docker build -t neonlabsorg/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg NEON_EVM_COMMIT=${NEON_EVM_COMMIT} \
    --build-arg PROXY_REVISION=${REVISION} \
    .
