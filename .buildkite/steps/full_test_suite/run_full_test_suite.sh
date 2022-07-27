#!/bin/bash

source .buildkite/steps/full_test_suite/utils.sh

# External addresses from previous step
PROXY_ADDR=`buildkite-agent meta-data get 'PROXY_IP'`
SOLANA_ADDR=`buildkite-agent meta-data get 'SOLANA_IP'`

# Create envirinment variables for tests
export PROXY_URL="http://${PROXY_ADDR}:9090/solana"
export FAUCET_URL="http://${PROXY_ADDR}:3333/request_neon"
export SOLANA_URL="http://${SOLANA_ADDR}:8899"

# Check variables
echo "External URL for proxy service: ${PROXY_URL}"
echo "External URL for faucet: ${FAUCET_URL}"
echo "External URL for solana: ${SOLANA_URL}"

# Set debug fts image name
export FTS_IMAGE="neonlabsorg/full_test_suite:debug"

# Start tests
echo Full test suite container name - ${FTS_CONTAINER_NAME}
docker-compose -f docker-compose/docker-compose-full-test-suite.yml pull
handle_error "Failed to pull full test suite docker image"
docker-compose -f docker-compose/docker-compose-full-test-suite.yml up
handle_error "Failed to run full test suite docker container"
FTS_RESULT=$(docker logs ${FTS_CONTAINER_NAME} | (grep -oP "(?<=Passing - )\d+" || echo 0))

# Retreive logs from local containers
docker cp ${FTS_CONTAINER_NAME}:/opt/allure-reports.tar.gz ./
handle_error "Failed to retreive allure logs from local container"
docker logs ${FTS_CONTAINER_NAME} > ./${FTS_CONTAINER_NAME}.log
handle_error "Failed to retreive test suite logs from local container"

# Retreive logs from remote instances
export SSH_KEY="~/.ssh/ci-stands"
export ARTIFACTS_LOGS="./logs"
mkdir -p $ARTIFACTS_LOGS
handle_error "Failed to create artifacts dir at: '$ARTIFACTS_LOGS'"

# solana
export SOLANA_ADDR=`buildkite-agent meta-data get "SOLANA_IP"`
ssh-keyscan -H $SOLANA_ADDR >> ~/.ssh/known_hosts
handle_error "Failed to retrieve ssh fingerprint"
echo "Upload logs for service: solana"
ssh -i ${SSH_KEY} ubuntu@${SOLANA_ADDR} 'sudo docker logs solana 2>&1 | pbzip2 > /tmp/solana.log.bz2'
handle_error "Failed to dump log for service: solana"
scp -i ${SSH_KEY} ubuntu@${SOLANA_ADDR}:/tmp/solana.log.bz2 ${ARTIFACTS_LOGS}
handle_error "Failed to retrieve log file from service: solana"

# proxy
export PROXY_ADDR=`buildkite-agent meta-data get "PROXY_IP"`
ssh-keyscan -H $PROXY_ADDR >> ~/.ssh/known_hosts
handle_error "Failed to retrieve ssh fingerprint"

declare -a services=("postgres" "dbcreation" "indexer" "proxy" "faucet")
for service in "${services[@]}"
do
   echo "Upload logs for service: $service"
   ssh -i ${SSH_KEY} ubuntu@${PROXY_ADDR} "sudo docker logs $service 2>&1 | pbzip2 > /tmp/$service.log.bz2"
   handle_error "Failed to dump log for service: $service"
   scp -i ${SSH_KEY} ubuntu@${PROXY_ADDR}:/tmp/$service.log.bz2 ${ARTIFACTS_LOGS}
   handle_error "Failed to retrieve log file from service: $service"
done

# Clean resources
docker-compose -f docker-compose/docker-compose-full-test-suite.yml rm -f
handle_error "Failed to tests cleanup"

# Results
echo Full test passing - ${FTS_RESULT}
echo Full test threshold - ${FTS_THRESHOLD}
echo Check if ${FTS_RESULT} is greater or equeal ${FTS_THRESHOLD}
test ${FTS_RESULT} -ge ${FTS_THRESHOLD}
