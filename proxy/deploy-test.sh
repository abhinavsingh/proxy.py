#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

curl -vX POST -H "Content-Type: application/json" -d '{"method":"eth_blockNumber","params":[],"id":93,"jsonrpc":"2.0"}' $PROXY_URL

echo "Deploy test success"
exit 0
