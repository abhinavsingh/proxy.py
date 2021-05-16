#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

# Refreshing cybercoredev/solana:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/solana:latest

# Refreshing cybercoredev/evm_loader:latest image is required to run .buildkite/steps/build-image.sh locally
docker pull cybercoredev/evm_loader:latest

docker build -t cybercoredev/proxy:${REVISION} .
