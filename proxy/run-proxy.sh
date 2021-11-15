#!/bin/bash

set -xeo pipefail

date

if [ "$CONFIG" == "ci" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://solana:8899"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=deploy
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=100
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=100000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.5"
  [[ -z "$USE_COMBINED_START_CONTINUE"  ]] && export USE_COMBINED_START_CONTINUE="NO"
  [[ -z "$CONTINUE_COUNT_FACTOR"        ]] && export CONTINUE_COUNT_FACTOR="3"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=0
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="postgres"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
elif [ "$CONFIG" == "local" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://localhost:8899"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=deploy
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=10
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.9"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=0
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
elif [ "$CONFIG" == "devnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.devnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=0
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="10"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
elif [ "$CONFIG" == "testnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.testnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$NEW_USER_AIRDROP_AMOUNT"      ]] && export NEW_USER_AIRDROP_AMOUNT=0
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="15"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE="1"
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
elif [ "$CONFIG" != "custom" ]; then
  exit 1
fi

[[ -z "$SOLANA_URL"               ]] && echo "SOLANA_URL is not set" && exit 1
[[ -z "$EVM_LOADER"               ]] && echo "EVM_LOADER is not set" && exit 1

echo SOLANA_URL=$SOLANA_URL

solana config set -u $SOLANA_URL

solana config get

for i in {1..30}; do
    if solana cluster-version; then break; fi
    sleep 2
done


ADDRESS=$(solana address || echo "no wallet")

if [ "$ADDRESS" == "no wallet" ]; then
  solana-keygen new --no-passphrase
fi

if ! solana account $(solana address); then
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
  solana program dump "$EVM_LOADER" ./evm_loader.dump
  /spl/bin/neon-cli --evm_loader="$EVM_LOADER" neon-elf-params ./evm_loader.dump
fi

echo "EVM_LOADER=$EVM_LOADER"


echo "A new token will be created. Creating token..."
export ETH_TOKEN_MINT=$(/spl/bin/spl-token create-token --owner /spl/bin/test_token_owner -- /spl/bin/test_token_keypair | grep -Po 'Creating token \K[^\n]*')
echo "ETH_TOKEN_MINT=$ETH_TOKEN_MINT"


echo "A new collateral pool accounts will be created. Creating accounts..."
solana -k /spl/bin/collateral-pool-keypair.json airdrop 1000
python3 /spl/bin/collateral_pool_generator.py /spl/bin/collateral-pool-keypair.json
export COLLATERAL_POOL_BASE=$(solana-keygen pubkey -f /spl/bin/collateral-pool-keypair.json)
echo "COLLATERAL_POOL_BASE=$COLLATERAL_POOL_BASE"


if [ "$NEW_USER_AIRDROP_AMOUNT" -gt 0 -a "$(spl-token balance "$ETH_TOKEN_MINT" || echo 0)" -eq 0 ]; then
	echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$ETH_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$ETH_TOKEN_MINT" $(("$NEW_USER_AIRDROP_AMOUNT"*1000)) --owner /spl/bin/test_token_owner -- "$TOKEN_ACCOUNT"
fi

echo "NEW_USER_AIRDROP_AMOUNT=$NEW_USER_AIRDROP_AMOUNT"


isArg() { case "$1" in "$2"|"$2="*) true;; *) false;; esac }
EXTRA_ARGS_TIMEOUT=' --timeout 300'
for val in $EXTRA_ARGS; do
    isArg $val '--timeout' && EXTRA_ARGS_TIMEOUT=''
done
EXTRA_ARGS+=$EXTRA_ARGS_TIMEOUT

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin $EXTRA_ARGS
