#!/bin/bash
set -euo pipefail

# External addresses from previous step
PROXY_ADDR=`buildkite-agent meta-data get 'PROXY_IP'`
SOLANA_ADDR=`buildkite-agent meta-data get 'SOLANA_IP'`

# Create envirinment variables for tests
export PROXY_URL="http://${PROXY_ADDR}:9091/solana"
export FAUCET_URL="http://${PROXY_ADDR}:3333/request_neon"
export SOLANA_URL="http://${SOLANA_ADDR}:8899"

# Check variables
echo "External URL for proxy service: ${PROXY_URL}"
echo "External URL for faucet: ${FAUCET_URL}"
echo "External URL for solana: ${SOLANA_URL}"

# Start tests
echo Full test suite container name - ${FTS_CONTAINER_NAME}
docker-compose -f docker-compose/docker-compose-full-test-suite.yml pull
docker-compose -f docker-compose/docker-compose-full-test-suite.yml up
FTS_RESULT=$(docker logs ${FTS_CONTAINER_NAME} | (grep -oP "(?<=Passing - )\d+" || echo 0))
# Retreive logs
docker cp ${FTS_CONTAINER_NAME}:/opt/allure-reports.tar.gz ./
docker logs ${FTS_CONTAINER_NAME} > ./${FTS_CONTAINER_NAME}.log
# Clean resources
docker-compose -f docker-compose/docker-compose-full-test-suite.yml rm -f

# Results
echo Full test passing - ${FTS_RESULT}
echo Full test threshold - ${FTS_THRESHOLD}
echo Check if ${FTS_RESULT} is greater or equeal ${FTS_THRESHOLD}
test ${FTS_RESULT} -ge ${FTS_THRESHOLD}
