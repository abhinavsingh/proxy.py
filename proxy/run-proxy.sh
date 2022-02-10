#!/bin/bash
COMPONENT=Proxy
echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} Start ${COMPONENT} service"

source proxy/run-set-env.sh ${COMPONENT}

echo "$(date "+%F %X.%3N") I $(basename $0):${LINENO} $$ ${COMPONENT}:StartScript {} run-proxy"
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin $EXTRA_ARGS
