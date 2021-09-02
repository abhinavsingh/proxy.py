#!/bin/bash

set -xeo pipefail

date

if [ "$CONFIG" == "local" ]; then
  [[ -z "$SOLANA_URL"               ]] export SOLANA_URL="http://localhost:8899"
  [[ -z "$EVM_LOADER"               ]] export EVM_LOADER=deploy
  [[ -z "$ETH_TOKEN_MINT"           ]] export ETH_TOKEN_MINT=deploy
  [[ -z "$COLLATERAL_POOL_BASE"     ]] export COLLATERAL_POOL_BASE=deploy
  [[ -z "$LOCAL_CLUSTER"            ]] export LOCAL_CLUSTER=local
  [[ -z "$EXTRA_GAS"                ]] export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"         ]] export NEON_CLI_TIMEOUT="0.5"
fi
if [ "$CONFIG" == "devnet" ]; then
  [[ -z "$SOLANA_URL"               ]] export SOLANA_URL="https://api.devnet.solana.com"
  [[ -z "$EVM_LOADER"               ]] unset EVM_LOADER
  [[ -z "$ETH_TOKEN_MINT"           ]] export ETH_TOKEN_MINT=89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g
  [[ -z "$COLLATERAL_POOL_BASE"     ]] export COLLATERAL_POOL_BASE=4sW3SZDJB7qXUyCYKA7pFL8eCTfm3REr8oSiKkww7MaT
  [[ -z "$LOCAL_CLUSTER"            ]] unset LOCAL_CLUSTER
  [[ -z "$EXTRA_GAS"                ]] export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"         ]] export NEON_CLI_TIMEOUT="10"
fi
if [ "$CONFIG" == "testnet" ]; then
  [[ -z "$SOLANA_URL"               ]] export SOLANA_URL="https://api.testnet.solana.com"
  [[ -z "$EVM_LOADER"               ]] unset EVM_LOADER
  [[ -z "$ETH_TOKEN_MINT"           ]] export ETH_TOKEN_MINT=89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g
  [[ -z "$COLLATERAL_POOL_BASE"     ]] export COLLATERAL_POOL_BASE=7SBdHNeF9FFYySEoszpjZXXQsAiwa5Lzpsz6nUJWusEx
  [[ -z "$LOCAL_CLUSTER"            ]] unset LOCAL_CLUSTER
  [[ -z "$EXTRA_GAS"                ]] export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"         ]] export NEON_CLI_TIMEOUT="15"
fi

echo SOLANA_URL=$SOLANA_URL

solana config set -u $SOLANA_URL

solana config get

for i in {1..10}; do
    if solana cluster-version; then break; fi
    sleep 2
done


ADDRESS=$(solana address || echo "no wallet")

if [ "$ADDRESS" == "no wallet" ]; then
  solana-keygen new --no-passphrase
  echo "airdropping..."
  solana airdrop 1000
  # check that balance >= 10 otherwise airdroping by 1 SOL up to 10
  BALANCE=$(solana balance | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1)
  while [ "$BALANCE" -lt 10 ]; do
    solana airdrop 1
    sleep 1
    BALANCE=$(solana balance | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1)
  done
fi

solana address
solana balance

export EVM_LOADER_TEST_NET_ID="eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU"

if [ -z "$EVM_LOADER" ]; then
  echo "EVM_LOADER is unset or set to the empty string. The pre-deployed Neon-evm will be used"
  export EVM_LOADER="$EVM_LOADER_TEST_NET_ID"
else
  if [ "$EVM_LOADER" == "deploy" ]; then
    echo "EVM_LOADER is set to load. A new Neon-evm will be deployed. deploying evm_loader..."
    solana program deploy --upgrade-authority /spl/bin/evm_loader-keypair.json /spl/bin/evm_loader.so > evm_loader_id
    export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
  else
    echo "EVM_LOADER is set. The specified Neon-evm will be used"
  fi
fi

echo "Use evm_loader with EVM_LOADER=$EVM_LOADER"


export ETH_TOKEN_MINT_TEST_NET_ID="HPsV9Deocecw3GeZv1FkAPNCBRfuVyfw9MMwjwRe1xaU"

if [ -z "$ETH_TOKEN_MINT" ]; then
  echo "ETH_TOKEN_MINT is unset or set to the empty string. The pre-deployed token mint will be used"
  export ETH_TOKEN_MINT="$ETH_TOKEN_MINT_TEST_NET_ID"
else
  if [ "$ETH_TOKEN_MINT" == "deploy" ]; then
    echo "ETH_TOKEN_MINT is set to load. A new token will be created. Creating token..."
    export ETH_TOKEN_MINT=$(/spl/bin/spl-token create-token --owner /spl/bin/test_token_owner -- /spl/bin/test_token_keypair | grep -Po 'Creating token \K[^\n]*')
  else
    echo "ETH_TOKEN_MINT is set. The specified token mint will be used"
  fi
fi

echo "Use eth token mint with ETH_TOKEN_MINT=$ETH_TOKEN_MINT"


# export COLLATERAL_POOL_BASE_TEST_NET_ID=""

# if [ -z "$COLLATERAL_POOL_BASE" ]; then
#   echo "COLLATERAL_POOL_BASE is unset or set to the empty string. The pre-deployed token mint will be used"
#   export COLLATERAL_POOL_BASE="$COLLATERAL_POOL_BASE_TEST_NET_ID"
# else
  if [ "$COLLATERAL_POOL_BASE" == "deploy" ]; then
    echo "COLLATERAL_POOL_BASE is set to create. A new collateral pool accounts will be created. Creating accounts..."
    #generate collateral pool accounts
    solana -k /spl/bin/collateral-pool-keypair.json airdrop 1000
    python3 /spl/bin/collateral_pool_generator.py /spl/bin/collateral-pool-keypair.json
    export COLLATERAL_POOL_BASE=$(solana-keygen pubkey -f /spl/bin/collateral-pool-keypair.json)
  else
    echo "COLLATERAL_POOL_BASE is set. The specified collateral pool will be used"
  fi
# fi

echo "Use collateral pool base with COLLATERAL_POOL_BASE=$COLLATERAL_POOL_BASE"


if [ "$LOCAL_CLUSTER" == "local" ]; then
  ACCOUNT=$(solana address)
  TOKEN_ACCOUNT=$(/spl/bin/spl-token create-account $ETH_TOKEN_MINT --owner $ACCOUNT | grep -Po 'Creating account \K[^\n]*')
  /spl/bin/spl-token mint $ETH_TOKEN_MINT 5000 --owner /spl/bin/test_token_owner -- $TOKEN_ACCOUNT
  /spl/bin/spl-token balance $ETH_TOKEN_MINT --owner $ACCOUNT
fi

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin
