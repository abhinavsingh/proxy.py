#!/bin/bash
COMPONENT=Proxy
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$SOLANA_URL" ]; then
  echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} SOLANA_URL is not set"
  exit 1
fi

solana config set -u $SOLANA_URL
ln -s /opt/proxy/operator-keypairs/id?*.json /root/.config/solana/

echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Dumping evm_loader and extracting ELF parameters"
export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
export $(/spl/bin/neon-cli --commitment confirmed --url $SOLANA_URL --evm_loader="$EVM_LOADER" neon-elf-params)

export NUM_ACCOUNTS=15
/spl/bin/create-test-accounts.sh $NUM_ACCOUNTS

echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} NEON_TOKEN_MINT=$NEON_TOKEN_MINT"

for i in $(seq 1 $NUM_ACCOUNTS); do
  ID_FILE="$HOME/.config/solana/id"
  if [ "$i" -gt "1" ]; then
    ID_FILE="${ID_FILE}${i}.json"
  else
    ID_FILE="${ID_FILE}.json"
  fi
done

proxy/run-proxy.sh
