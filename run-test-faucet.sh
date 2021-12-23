#!/bin/bash

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

if [ -z "$TEST_FAUCET_INIT_NEON_BALANCE" ]; then
    echo "TEST_FAUCET_INIT_NEON_BALANCE is not set"
    exit 1
fi

solana config set -u "$SOLANA_URL"

echo "Extracting NEON-EVM's ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

echo "Generating new account for operate with faucet service"
rm /$HOME/.config/solana/id.json
/spl/bin/create-test-accounts.sh 1

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
    echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$NEON_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$NEON_TOKEN_MINT" $TEST_FAUCET_INIT_NEON_BALANCE --owner /spl/bin/evm_loader-keypair.json -- "$TOKEN_ACCOUNT"
fi

./run-faucet.sh
