#!/bin/bash
COMPONENT=Indexer
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$EVM_LOADER" ]; then
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER=$EVM_LOADER"
fi
export INDEXER_MODE='true'

source proxy/run-set-env.sh

python3 -m proxy
