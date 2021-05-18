#!/bin/bash

date

echo SOLANA_URL=$SOLANA_URL

solana-keygen new --no-passphrase

solana config set -u $SOLANA_URL

solana config get

for i in {1..10}; do
    if solana cluster-version; then break; fi
    sleep 2
done

echo airdropping...
solana airdrop 1000

echo deploying evm_loader...
solana-deploy deploy /spl/bin/evm_loader.so > evm_loader_id
export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
echo EVM_LOADER=$EVM_LOADER

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin --num-workers=1
