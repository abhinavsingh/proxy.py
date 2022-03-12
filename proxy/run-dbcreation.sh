#!/bin/bash
COMPONENT="dbcreation"
echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

if [ -z "$EVM_LOADER" ]; then
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} Extracting EVM_LOADER address from keypair file..."
    export EVM_LOADER=$(solana address -k /spl/bin/evm_loader-keypair.json)
    echo "$(date "+%F %X.%3N") I $(basename "$0"):${LINENO} $$ ${COMPONENT}:StartScript {} EVM_LOADER=$EVM_LOADER"
fi

echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} dbcreation"

export PGPASSWORD=${POSTGRES_PASSWORD}
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} -a -f proxy/db/scheme.sql
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} --command "\\dt+ public.*"
psql -h ${POSTGRES_HOST} ${POSTGRES_DB} ${POSTGRES_USER} --command "\\d+ public.*"
