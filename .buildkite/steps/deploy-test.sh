#!/bin/bash
set -euo pipefail

wait-for-proxy()
{
  for i in {1..10}; do
      if curl -s --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","params":[],"id":93,"jsonrpc":"2.0"}' $PROXY_URL > /dev/null;
      then
        echo `date +%H:%M:%S`" proxy is available"
        return 0
      fi
      echo `date +%H:%M:%S`" proxy is unavailable - sleeping"
      sleep 60
  done

  echo `date +%H:%M:%S`" proxy is unavailable - time is over"
  return 9847
}

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

SOLANA_URL=http://solana:8899
PROXY_URL=http://127.0.0.1:9090/solana
#PROXY_URL=http://proxy:9090/solana

echo "Wait proxy..." && wait-for-proxy
echo "Run tests..."
docker run --rm --network proxy_net -ti \
     -e SOLANA_URL \
     -e PROXY_URL \
     --entrypoint ./proxy/deploy-test.sh \
     ${EXTRA_ARGS:-} \
     $PROXY_IMAGE
echo "Run tests return"
exit 0
