#!/bin/bash
COMPONENT="${1:-Undefined}"
set -xeo pipefail

echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Init environment set"

if [ "$CONFIG" == "ci" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://solana:8899"
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.5"
  [[ -z "$CONTINUE_COUNT_FACTOR"        ]] && export CONTINUE_COUNT_FACTOR="3"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="postgres"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$START_SLOT"                   ]] && export START_SLOT="LATEST"
  [[ -z "$CONFIRM_TIMEOUT"              ]] && export CONFIRM_TIMEOUT=10
  [[ -z "$PERM_ACCOUNT_LIMIT"           ]] && export PERM_ACCOUNT_LIMIT=2
elif [ "$CONFIG" == "local" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="http://localhost:8899"
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="0.9"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=10
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$START_SLOT"                   ]] && export START_SLOT=0
  [[ -z "$CONFIRM_TIMEOUT"              ]] && export CONFIRM_TIMEOUT=10
  [[ -z "$PERM_ACCOUNT_LIMIT"           ]] && export PERM_ACCOUNT_LIMIT=2
elif [ "$CONFIG" == "devnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.devnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="10"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$START_SLOT"                   ]] && export START_SLOT="LATEST"
  [[ -z "$CONFIRM_TIMEOUT"              ]] && export CONFIRM_TIMEOUT=30
  [[ -z "$PERM_ACCOUNT_LIMIT"           ]] && export PERM_ACCOUNT_LIMIT=16
elif [ "$CONFIG" == "testnet" ]; then
  [[ -z "$SOLANA_URL"                   ]] && export SOLANA_URL="https://api.testnet.solana.com"
  [[ -z "$EVM_LOADER"                   ]] && export EVM_LOADER=eeLSJgWzzxrqKv1UxtRVVH8FX3qCQWUs9QuAjJpETGU
  [[ -z "$EXTRA_GAS"                    ]] && export EXTRA_GAS=0
  [[ -z "$NEON_CLI_TIMEOUT"             ]] && export NEON_CLI_TIMEOUT="15"
  [[ -z "$MINIMAL_GAS_PRICE"            ]] && export MINIMAL_GAS_PRICE=1
  [[ -z "$POSTGRES_HOST"                ]] && export POSTGRES_HOST="localhost"
  [[ -z "$CANCEL_TIMEOUT"               ]] && export CANCEL_TIMEOUT=60
  [[ -z "$RETRY_ON_FAIL"                ]] && export RETRY_ON_FAIL=10
  [[ -z "$START_SLOT"                   ]] && export START_SLOT="LATEST"
  [[ -z "$CONFIRM_TIMEOUT"              ]] && export CONFIRM_TIMEOUT=30
  [[ -z "$PERM_ACCOUNT_LIMIT"           ]] && export PERM_ACCOUNT_LIMIT=16
elif [ "$CONFIG" != "custom" ]; then
  exit 1
fi

[[ -z "$SOLANA_URL"               ]] && echo "$(date "+%F %X.%3N") E $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} SOLANA_URL is not set" && exit 1
[[ -z "$EVM_LOADER"               ]] && echo "$(date "+%F %X.%3N") E $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER is not set" && exit 1

solana config set -u $SOLANA_URL

isArg() { case "$1" in "$2"|"$2="*) true;; *) false;; esac }
EXTRA_ARGS_TIMEOUT=' --timeout 300'
for val in $EXTRA_ARGS; do
    isArg $val '--timeout' && EXTRA_ARGS_TIMEOUT=''
done
EXTRA_ARGS+=$EXTRA_ARGS_TIMEOUT

export PROMETHEUS_MULTIPROC_DIR=$(mktemp -d)
