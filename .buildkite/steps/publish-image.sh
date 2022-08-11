#!/bin/bash
set -euo pipefail

source .buildkite/steps/revision.sh

docker images

docker login -u $DHUBU -p $DHUBP

if [[ ${BUILDKITE_BRANCH} == "master" ]]; then
    TAG=stable
elif [[ ${BUILDKITE_BRANCH} == "develop" ]]; then
    TAG=latest
else
    TAG=${BUILDKITE_BRANCH}
fi

docker pull neonlabsorg/proxy:${REVISION}
docker tag neonlabsorg/proxy:${REVISION} neonlabsorg/proxy:${TAG}
docker push neonlabsorg/proxy:${TAG}
