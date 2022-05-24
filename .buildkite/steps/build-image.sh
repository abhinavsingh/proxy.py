#!/bin/bash
set -euo pipefail

. .buildkite/steps/revision.sh

echo "Neon Proxy revision=${REVISION}"

# Refreshing neonlabsorg/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/evm_loader:${NEON_EVM_COMMIT}
# Refreshing neonlabsorg/evm_loader:ci-proxy-caller-program image is required to run .buildkite/steps/build-image.sh locally
docker pull neonlabsorg/evm_loader:ci-proxy-caller-program

docker build -t neonlabsorg/proxy:${REVISION} \
    --build-arg NEON_EVM_COMMIT=${NEON_EVM_COMMIT} \
    --build-arg PROXY_REVISION=${REVISION} \
    .
