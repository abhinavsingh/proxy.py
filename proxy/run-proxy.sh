#!/bin/bash

set -xeo pipefail

date

if [ "$CONFIG" == "ci" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://solana:8899"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=deploy
  [[ -z "$ETH_TOKEN_MINT"               ]] && export ETH_TOKEN_MINT=deploy
  [[ -z "$COLLATERAL_POOL_BASE"         ]] && export COLLATERAL_POOL_BASE=deploy
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=100
  [[ -z "$NEON_CHAIN_ID"                ]] && export NEON_CHAIN_ID=0x6f
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=100000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.5"
  [[ -z "$USE_COMBINED_START_CONTINUE"  ]] && export USE_COMBINED_START_CONTINUE="YES"
  [[ -z "$CONTINUE_COUNT_FACTOR"        ]] && export CONTINUE_COUNT_FACTOR="5"
elif [ "$CONFIG" == "local" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://localhost:8899"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=deploy
  [[ -z "$ETH_TOKEN_MINT"               ]] && export ETH_TOKEN_MINT=deploy
  [[ -z "$COLLATERAL_POOL_BASE"         ]] && export COLLATERAL_POOL_BASE=deploy
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=10
  [[ -z "$NEON_CHAIN_ID"                ]] && export NEON_CHAIN_ID=0x6f
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.9"
elif [ "$CONFIG" == "devnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.devnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$ETH_TOKEN_MINT"               ]] && export ETH_TOKEN_MINT=89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g
  [[ -z "$COLLATERAL_POOL_BASE"         ]] && export COLLATERAL_POOL_BASE=7SBdHNeF9FFYySEoszpjZXXQsAiwa5Lzpsz6nUJWusEx
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=0
  [[ -z "$NEON_CHAIN_ID"                ]] && export NEON_CHAIN_ID=0x6e
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="10"
elif [ "$CONFIG" == "testnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.testnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$ETH_TOKEN_MINT"               ]] && export ETH_TOKEN_MINT=89dre8rZjLNft7HoupGiyxu3MNftR577ZYu8bHe2kK7g
  [[ -z "$COLLATERAL_POOL_BASE"         ]] && export COLLATERAL_POOL_BASE=7SBdHNeF9FFYySEoszpjZXXQsAiwa5Lzpsz6nUJWusEx
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=0
  [[ -z "$NEON_CHAIN_ID"                ]] && export NEON_CHAIN_ID=0x6f
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="15"
elif [ "$CONFIG" != "custom" ]; then
  exit 1
fi

[[ -z "$SOLANA_URL"               ]] && echo "SOLANA_URL is not set" && exit 1
[[ -z "$EVM_LOADER"               ]] && echo "EVM_LOADER is not set" && exit 1
[[ -z "$ETH_TOKEN_MINT"           ]] && echo "ETH_TOKEN_MINT is not set" && exit 1
[[ -z "$COLLATERAL_POOL_BASE"     ]] && echo "COLLATERAL_POOL_BASE is not set" && exit 1
[[ -z "$NEON_CHAIN_ID"            ]] && echo "NEON_CHAIN_ID is not set" && exit 1

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


if [ "$EVM_LOADER" == "deploy" ]; then
  echo "EVM_LOADER is set to load. A new Neon-evm will be deployed. deploying evm_loader..."
  solana program deploy --upgrade-authority /spl/bin/evm_loader-keypair.json /spl/bin/evm_loader.so > evm_loader_id
  export EVM_LOADER=$(cat evm_loader_id | sed '/Program Id: \([0-9A-Za-z]\+\)/,${s//\1/;b};s/^.*$//;$q1')
fi

echo "EVM_LOADER=$EVM_LOADER"


if [ "$ETH_TOKEN_MINT" == "deploy" ]; then
  echo "ETH_TOKEN_MINT is set to load. A new token will be created. Creating token..."
  export ETH_TOKEN_MINT=$(/spl/bin/spl-token create-token --owner /spl/bin/test_token_owner -- /spl/bin/test_token_keypair | grep -Po 'Creating token \K[^\n]*')
fi

echo "ETH_TOKEN_MINT=$ETH_TOKEN_MINT"


if [ "$COLLATERAL_POOL_BASE" == "deploy" ]; then
  echo "COLLATERAL_POOL_BASE is set to create. A new collateral pool accounts will be created. Creating accounts..."
  #generate collateral pool accounts
  solana -k /spl/bin/collateral-pool-keypair.json airdrop 1000
  python3 /spl/bin/collateral_pool_generator.py /spl/bin/collateral-pool-keypair.json
  export COLLATERAL_POOL_BASE=$(solana-keygen pubkey -f /spl/bin/collateral-pool-keypair.json)
fi

echo "COLLATERAL_POOL_BASE=$COLLATERAL_POOL_BASE"


if [ "$NEW_USER_AIRDROP_AMOUNT" -gt 0 -a "$(spl-token balance "$ETH_TOKEN_MINT" || echo 0)" -eq 0 ]; then
	echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$ETH_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$ETH_TOKEN_MINT" $(("$NEW_USER_AIRDROP_AMOUNT"*1000)) --owner /spl/bin/test_token_owner -- "$TOKEN_ACCOUNT"
fi

echo "NEW_USER_AIRDROP_AMOUNT=$NEW_USER_AIRDROP_AMOUNT"


echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin
