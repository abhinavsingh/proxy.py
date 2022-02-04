#!/bin/bash

if [ -z "$EVM_LOADER" ]; then
    echo "Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "EVM_LOADER=$EVM_LOADER"
fi
export INDEXER_MODE='true'

source proxy/run-set-env.sh

python3 -m proxy
