#!/bin/bash
COMPONENT=Faucet
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$SOLANA_URL" ]; then
  echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} SOLANA_URL is not set"
  exit 1
fi

if [ -z "$TEST_FAUCET_INIT_NEON_BALANCE" ]; then
    echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} TEST_FAUCET_INIT_NEON_BALANCE is not set"
    exit 1
fi

solana config set -u "$SOLANA_URL"

echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Extracting NEON-EVM's ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Generating new account for operate with faucet service"
rm /$HOME/.config/solana/id.json
/spl/bin/create-test-accounts.sh 1

if [ "$(spl-token balance "$NEON_TOKEN_MINT" || echo 0)" -eq 0 ]; then
  echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Create balance and mint token"
	TOKEN_ACCOUNT=$( (spl-token create-account "$NEON_TOKEN_MINT" || true) | grep -Po 'Creating account \K[^\n]*')
	echo "$(date "+%F %X.%3N") E $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
	spl-token mint "$NEON_TOKEN_MINT" $TEST_FAUCET_INIT_NEON_BALANCE --owner /spl/bin/evm_loader-keypair.json -- "$TOKEN_ACCOUNT"
fi

./run-faucet.sh
