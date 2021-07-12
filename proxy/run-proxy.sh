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

export EVM_LOADER_TEST_NET_ID="A5CqSrY2ca3Sykqt69i6nvCWzyKKcupSNLCCzdDqDo3n"

if [ "$EVM_LOADER" == "$EVM_LOADER_TEST_NET_ID" ]; then
   echo "The default Neon-evm will be used"
   export EVM_LOADER="$EVM_LOADER_TEST_NET_ID"
else
  if [ -z "${EVM_LOADER}" ]; then
    echo "EVM_LOADER is unset or set to the empty string"
    echo airdropping...
    solana airdrop 1000

    echo deploying evm_loader...
    solana deploy /spl/bin/evm_loader.so > evm_loader_id
    export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
    echo EVM_LOADER=$EVM_LOADER
  fi
fi

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin
