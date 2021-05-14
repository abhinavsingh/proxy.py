#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","params":[],"id":93,"jsonrpc":"2.0"}' $PROXY_URL

echo "add your tests there"

echo "Deploy test success"
exit 0
