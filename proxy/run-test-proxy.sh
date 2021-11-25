#!/bin/bash

if [ -z "$SOLANA_URL" ]; then
  echo "SOLANA_URL is not set"
  exit 1
fi

solana config set -u $SOLANA_URL

echo "Dumping evm_loader and extracting ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

/spl/bin/create-test-accounts.sh 1

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
  [[ -z "$NEW_USER_AIRDROP_AMOUNT" ]] && export NEW_USER_AIRDROP_AMOUNT=100
  echo "NEW_USER_AIRDROP_AMOUNT=$NEW_USER_AIRDROP_AMOUNT"
	echo 'Create balance and mint token'
	TOKEN_ACCOUNT=$( (spl-token create-account "$NEON_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$NEON_TOKEN_MINT" $(("$NEW_USER_AIRDROP_AMOUNT"*1000)) --owner /spl/bin/evm_loader-keypair.json -- "$TOKEN_ACCOUNT"
fi

proxy/run-proxy.sh
