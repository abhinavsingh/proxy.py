#!/bin/bash

# proxy.py
# ~~~~~~~~
# ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
#     proxy server for Application debugging, testing and development.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
# Usage
# ./chrome_with_proxy <proxy-py-address=localhost:8899>

PROXY_PY_ADDR=$1
if [[ -z "$PROXY_PY_ADDR" ]]; then
  PROXY_PY_ADDR="localhost:8899"
fi

/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --no-first-run \
  --no-default-browser-check \
  --user-data-dir="$(mktemp -d -t 'chrome-remote_data_dir')" \
  --proxy-server=${PROXY_PY_ADDR} \
  --ignore-urlfetcher-cert-requests \
  --ignore-certificate-errors
