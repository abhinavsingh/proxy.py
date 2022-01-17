#!/bin/bash

if [ -z "$EVM_LOADER" ]; then
    echo "Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "EVM_LOADER=$EVM_LOADER"
fi
export AIRDROPPER_MODE='true'
[[ -z "$FINALIZED" ]] && export FINALIZED="confirmed"

python3 -m proxy
