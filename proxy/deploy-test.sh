#!/bin/bash
set -xeuo pipefail

if [ "${SKIP_PREPARE_DEPLOY_TEST:-NO}" != "YES" ]; then
    SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
    source ${SCRIPT_PATH}/prepare-deploy-test.sh
fi

echo "Deploy test ..."
export $(cat .test-env | xargs)
python3 -m unittest discover -v -p "${TESTNAME:-test_*.py}"
echo "Deploy test success"

exit 0
