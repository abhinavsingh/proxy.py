#!/bin/bash
set -euo pipefail

while getopts t: option; do
case "${option}" in
    t) IMAGETAG=${OPTARG};;
    *) echo "Usage: $0 [OPTIONS]. Where OPTIONS can be:"
       echo "    -t <IMAGETAG>  tag for cybercoredev/proxy Docker-image"
       exit 1;;
esac
done

REVISION=$(git rev-parse HEAD)
PROXY_IMAGE=cybercoredev/proxy:${IMAGETAG:-$REVISION}

docker-compose -f proxy/docker-compose-test.yml up -d

function cleanup_docker {
    echo "Cleanup docker-compose..."
    docker-compose -f proxy/docker-compose-test.yml down
    echo "Cleanup docker-compose done."
}
trap cleanup_docker EXIT
sleep 10

echo "Run tests..."
cmd='python3 -m unittest discover -v --start-directory /opt/commun.contracts/scripts/'
docker run --rm --network dc-net -ti \
     -e PROXY_URL=http://proxy:9090/solana \
     ${EXTRA_ARGS:-} \
     $PROXY_IMAGE '/opt/deploy-test.sh'
echo "Run tests return"

exit $?
