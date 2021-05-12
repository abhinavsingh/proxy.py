#!/bin/bash

#SOLANA_URL= $1

date

echo SOLANA_URL=$SOLANA_URL

solana-keygen new --no-passphrase

solana config set -u $SOLANA_URL

solana config get

for i in {1..10}; do
    if solana cluster-version; then break; fi
    sleep 2
done

solana airdrop 1000

solana-deploy deploy /spl/bin/evm_loader.so > evm_loader_id

export EVM_LOADER=$(cat evm_loader_id | tail -n 1 | python3 -c 'import sys, json; data=json.load(sys.stdin); print(data["programId"]);')


echo run-proxy
echo EVM_LOADER=$EVM_LOADER
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin --num-workers=1
