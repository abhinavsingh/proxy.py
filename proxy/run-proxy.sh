#!/bin/bash

set -xeo pipefail

date

if [ "$CONFIG" == "ci" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://solana:8899"
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=100000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.5"
  [[ -z "$CONTINUE_COUNT_FACTOR"        ]] && export CONTINUE_COUNT_FACTOR="3"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=0
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="postgres"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
  [[ -z "$RETRY_ON_BLOCKED"             ]] && export RETRY_ON_BLOCKED=32
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$FINALIZED"                    ]] && export FINALIZED="finalized"
elif [ "$CONFIG" == "local" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://localhost:8899"
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.9"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=0
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
  [[ -z "$RETRY_ON_BLOCKED"             ]] && export RETRY_ON_BLOCKED=32
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$FINALIZED"                    ]] && export FINALIZED="finalized"
elif [ "$CONFIG" == "devnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.devnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="10"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
  [[ -z "$RETRY_ON_BLOCKED"             ]] && export RETRY_ON_BLOCKED=32
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$FINALIZED"                    ]] && export FINALIZED="finalized"
elif [ "$CONFIG" == "testnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.testnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=90000
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="15"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE="1"
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
  [[ -z "$RETRY_ON_BLOCKED"             ]] && export RETRY_ON_BLOCKED=32
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$FINALIZED"                    ]] && export FINALIZED="finalized"
elif [ "$CONFIG" != "custom" ]; then
  exit 1
fi

[[ -z "$SOLANA_URL"               ]] && echo "SOLANA_URL is not set" && exit 1
[[ -z "$EVM_LOADER"               ]] && echo "EVM_LOADER is not set" && exit 1

solana config set -u $SOLANA_URL

isArg() { case "$1" in "$2"|"$2="*) true;; *) false;; esac }
EXTRA_ARGS_TIMEOUT=' --timeout 300'
for val in $EXTRA_ARGS; do
    isArg $val '--timeout' && EXTRA_ARGS_TIMEOUT=''
done
EXTRA_ARGS+=$EXTRA_ARGS_TIMEOUT

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin $EXTRA_ARGS
