#!/bin/bash
COMPONENT=Airdropper
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

[[ -z "$FINALIZED" ]] && export FINALIZED="confirmed"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
python3 -m proxy
