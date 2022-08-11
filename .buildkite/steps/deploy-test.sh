#!/bin/bash
set -euo pipefail

while getopts t: option; do
case "${option}" in
    t) IMAGETAG=${OPTARG};;
    *) echo "Usage: $0 [OPTIONS]. Where OPTIONS can be:"
       echo "    -t <IMAGETAG>  tag for neonlabsorg/proxy Docker-image"
       exit 1;;
esac
done

source .buildkite/steps/revision.sh

[ "${SKIP_DOCKER_PULL}" == "YES" ] || docker-compose -f proxy/docker-compose-test.yml pull

function cleanup_docker {
    echo
    echo "Cleanup docker-compose..."
    docker-compose -f proxy/docker-compose-test.yml down -t 1
    echo "Cleanup docker-compose done."

    echo
    echo "Removing temporary data volumes..."
    docker volume prune -f
    echo "Removing temporary data done."
}

function dump_docker_logs {
    if docker logs proxy >proxy.log 2>&1; then echo "proxy logs saved"; fi
    if docker logs solana >solana.log 2>&1; then echo "solana logs saved"; fi
    if docker logs proxy_program_loader >proxy_program_loader.log 2>&1; then echo "proxy_program_loader logs saved"; fi
    if docker logs dbcreation >dbcreation.log 2>&1; then echo "dbcreation logs saved"; fi
    if docker logs faucet >faucet.log 2>&1; then echo "faucet logs saved"; fi
    if docker logs airdropper >airdropper.log 2>&1; then echo "airdropper logs saved"; fi
    if docker logs indexer >indexer.log 2>&1; then echo "indexer logs saved"; fi
    if docker logs deploy_contracts >deploy_contracts.log 2>&1; then echo "deploy_contracts logs saved"; fi
    if docker logs proxy_program >proxy_program.log 2>&1; then echo "proxy_program.log logs saved"; fi

    cleanup_docker
}

trap dump_docker_logs EXIT

cleanup_docker

echo
if ! docker-compose -f proxy/docker-compose-test.yml up -d; then
    echo "docker-compose failed to start"
    exit 1
fi

function wait-for-faucet {
    declare FAUCET_URL=$(docker exec proxy bash -c 'echo "${FAUCET_URL}"')
    declare FAUCET_IPPORT=$(echo "${FAUCET_URL}" | cut -d / -f 3)
    declare FAUCET_IP=$(echo "${FAUCET_IPPORT}" | cut -d : -f 1)
    declare FAUCET_PORT=$(echo "${FAUCET_IPPORT}" | cut -d : -f 2)

    echo
    echo "`date +%H:%M:%S` Wait faucet ${FAUCET_IPPORT}..."
    for i in {1..100}; do
        if docker exec proxy nc -zvw1 "${FAUCET_IP}" "${FAUCET_PORT}"; then
            echo `date +%H:%M:%S`" faucet ${FAUCET_IPPORT} is available"
            return 0
        fi
        echo `date +%H:%M:%S`" faucet ${FAUCET_IPPORT} is unavailable - sleeping"
        sleep 1
    done

    echo `date +%H:%M:%S`" faucet ${FAUCET_IPPORT} is unavailable - time is over"
    return 9847
}
wait-for-faucet

function run_uniswap_test {
    export FAUCET_URL=$(docker exec proxy bash -c 'echo "${FAUCET_URL}"')
    echo
    echo "Run uniswap tests..."
    echo "FAUCET_URL ${FAUCET_URL}"

    declare UNISWAP_V2_CORE_IMAGE=neonlabsorg/uniswap-v2-core:${UNISWAP_V2_CORE_COMMIT}
    [ "${SKIP_DOCKER_PULL}" == "YES" ] || docker pull "${UNISWAP_V2_CORE_IMAGE}"

    docker run --rm --network=container:proxy \
        -e FAUCET_URL \
        --entrypoint ./deploy-test.sh \
        ${EXTRA_ARGS:-} \
        $UNISWAP_V2_CORE_IMAGE \
        all
}
export -f run_uniswap_test

function run_test {
    declare TESTNAME="${1}"
    if [ "${TESTNAME}" == "UNISWAP" ]; then
        run_uniswap_test
    else
        docker exec -e SKIP_PREPARE_DEPLOY_TEST=YES -e TESTNAME=${TESTNAME} proxy ./proxy/deploy-test.sh ${EXTRA_ARGS:-}
    fi
}
export -f run_test

function get_test_list {
    echo "UNISWAP"
    docker exec proxy find . -type f -name "test_*.py" -printf "%f\n"
}
export -f get_test_list

echo
echo "Run tests in parallel. "

docker cp proxy:/usr/bin/parallel ./parallel
docker exec proxy ./proxy/prepare-deploy-test.sh ${EXTRA_ARGS:-}
if [[ -z "${UNITTEST_TESTNAME:=}" ]]; then
    get_test_list | ./parallel --halt now,fail=1 run_test {}
else
    run_test "test_${UNITTEST_TESTNAME}.py"
fi

echo "Run tests return"
exit 0
