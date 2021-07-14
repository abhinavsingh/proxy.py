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

export EVM_LOADER_TEST_NET_ID="eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU"

if [ "${EVM_LOADER}" == "deploy" ]; then
  echo "EVM_LOADER is set to load"
  echo "A new Neon-evm will be deployed"
  echo airdropping...
  solana airdrop 1000
  # check that balance > 20 otherwise airdroping by 1 SOL up to 20
  set `solana balance|tr '.' ' '`
  while [ "$1" -lt 20 ]; do solana airdrop 1; sleep 1; set `solana balance|tr '.' ' '`; done

  echo deploying evm_loader...
  solana deploy /spl/bin/evm_loader.so > evm_loader_id
  export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
else
  if [ -z "${EVM_LOADER}" ]; then
    echo "EVM_LOADER is unset or set to the empty string"
    echo "The pre-deployed Neon-evm will be used"
    export EVM_LOADER="$EVM_LOADER_TEST_NET_ID"
  else
    echo "EVM_LOADER is set"
    echo "The specified Neon-evm will be used"
  fi
fi

echo "Use evm_loader with EVM_LOADER=$EVM_LOADER"

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin
