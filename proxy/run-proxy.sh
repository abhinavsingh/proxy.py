#!/bin/bash

source proxy/run-set-env.sh

echo run-proxy
python3 -m proxy --hostname 0.0.0.0 --port 9090 --enable-web-server --plugins proxy.plugin.SolanaProxyPlugin $EXTRA_ARGS
