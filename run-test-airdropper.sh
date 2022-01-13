#!/bin/bash

export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
python3 -m proxy
