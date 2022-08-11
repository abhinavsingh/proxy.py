#!/bin/bash
set -xeuo pipefail

echo "Prepare deploying of tests..."

curl -v --header "Content-Type: application/json" --data '{"method":"eth_blockNumber","id":1,"jsonrpc":"2.0","params":[]}' "${PROXY_URL}"

solana config get
solana address || solana-keygen new --no-passphrase
solana airdrop 1000
solana balance

/spl/bin/neon-cli --commitment confirmed --url "${SOLANA_URL}" --evm_loader "${EVM_LOADER}" neon-elf-params > .test-env
echo "TEST_PROGRAM=$(solana address -k /spl/bin/proxy_program-keypair.json)" >> .test-env

export $(cat .test-env | xargs)
echo "ETH_TOKEN_MINT=${NEON_TOKEN_MINT}" >> .test-env

echo "Done preparing of deploying of tests"
