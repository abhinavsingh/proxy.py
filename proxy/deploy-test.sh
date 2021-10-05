#!/bin/bash
set -xeuo pipefail

echo "Deploy test..."

solana-keygen new --no-passphrase --force
export $(/spl/bin/neon-cli --evm_loader JxujFZpNBPADbfw2MnPPgnnFGruzp2ELSFWPQgrjz5D neon-elf-params /spl/bin/evm_loader.so | grep NEON_REVISION | xargs)

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' $PROXY_URL

python3 -m unittest discover -v -p 'test*.py'

echo "Deploy test success"
exit 0
