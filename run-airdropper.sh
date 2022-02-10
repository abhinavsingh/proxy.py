#!/bin/bash
COMPONENT=Airdropper
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$EVM_LOADER" ]; then
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER=$EVM_LOADER"
fi
export AIRDROPPER_MODE='true'
[[ -z "$FINALIZED" ]] && export FINALIZED="confirmed"

python3 -m proxy
