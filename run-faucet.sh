#!/bin/sh

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

echo "Extracting NEON-EVM's ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

BALANCE=$(solana balance | tr '.' '\t'| tr '[:space:]' '\t' | cut -f1)
if [ "$BALANCE" -eq 0 ]; then
    echo "SOL balance is 0"
    exit 1
fi

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
    echo "NEON balance is 0"
    exit 1
fi

faucet run