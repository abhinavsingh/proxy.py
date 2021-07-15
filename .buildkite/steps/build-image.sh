#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

set ${SOLANA_REVISION:=v1.6.9-resources}
set ${EVM_LOADER_REVISION:=a52ae02933f6ea66d8dcd435100c6e9ef61c5bdb}

# Refreshing cybercoredev/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/solana:${SOLANA_REVISION}

# Refreshing cybercoredev/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/evm_loader:${EVM_LOADER_REVISION}

docker build -t cybercoredev/proxy:${REVISION} \
    --build-arg SOLANA_REVISION=${SOLANA_REVISION} \
    --build-arg EVM_LOADER_REVISION=${EVM_LOADER_REVISION} \
    .
