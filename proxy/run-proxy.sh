#!/bin/bash
set -xeo pipefail

date

echo SOLANA_URL=$SOLANA_URL

solana config set -u $SOLANA_URL

solana config get

for i in {1..10}; do
    if solana cluster-version; then break; fi
    sleep 2
done

solana address || solana-keygen new --no-passphrase
echo "The following wallet will be used:" && solana address

export EVM_LOADER_TEST_NET_ID="eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU"

echo "airdropping..."
solana airdrop 1000
# check that balance >= 10 otherwise airdroping by 1 SOL up to 10
BALANCE=`solana balance | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1`
while [ "$BALANCE" -lt 10 ]; do
  solana airdrop 1
  sleep 1
  BALANCE=`solana balance | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1`
done

if [ -z "$EVM_LOADER" ]; then
  echo "EVM_LOADER is unset or set to the empty string
        The pre-deployed Neon-evm will be used"
  export EVM_LOADER="$EVM_LOADER_TEST_NET_ID"
else
  if [ "$EVM_LOADER" == "deploy" ]; then
    echo "EVM_LOADER is set to load
          A new Neon-evm will be deployed
          deploying evm_loader..."
    solana deploy /spl/bin/evm_loader.so > evm_loader_id
    export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
  else
    echo "EVM_LOADER is set
          The specified Neon-evm will be used"
  fi
fi

echo "Use evm_loader with EVM_LOADER=$EVM_LOADER"

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin
