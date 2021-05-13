#!/bin/bash
set -euo pipefail

REVISION=$(git rev-parse HEAD)

docker images

docker login -u=${DHUBU} -p=${DHUBP}

docker push cybercoredev/proxy:${REVISION}

if [[ ${BUILDKITE_BRANCH} == "40-proxy-docker" ]]; then
    docker tag cybercoredev/proxy:${REVISION} cybercoredev/proxy:latest
    docker push cybercoredev/proxy:latest
fi


