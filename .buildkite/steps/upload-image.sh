#!/bin/bash
set -euo pipefail

source .buildkite/steps/revision.sh

docker images

docker login -u=${DHUBU} -p=${DHUBP}

docker push neonlabsorg/proxy:${REVISION}
