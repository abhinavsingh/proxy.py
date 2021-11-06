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

/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --no-first-run \
  --no-default-browser-check \
  --remote-debugging-port=9222 \
  --user-data-dir="$(mktemp -d -t 'chrome-remote_data_dir')"
