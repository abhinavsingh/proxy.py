#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' $PROXY_URL

python3 -m unittest discover -v -p 'test*.py'

echo "Deploy test success"
exit 0
