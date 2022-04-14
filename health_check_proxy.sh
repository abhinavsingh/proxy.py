#!/bin/bash

curl --location --request POST 'http://proxy:9090/solana' \
--header 'Content-Type: application/json' \
--data-raw '{"jsonrpc":"2.0", "method":"net_version", "params":[], "id":1 }'