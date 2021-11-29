#!/bin/bash
#
# proxy.py
# ~~~~~~~~
# ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
#     proxy server for Application debugging, testing and development.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
# Usage
# ./monitor_open_files <proxy-py-pid>
#
# Alternately, just run:
# watch -n 1 'lsof -i TCP:8899 | grep -v LISTEN'

PROXY_PY_PID=$1
if [[ -z "$PROXY_PY_PID" ]]; then
  echo "PROXY_PY_PID required as argument."
  exit 1
fi

OPEN_FILES_BY_MAIN=$(lsof -p "$PROXY_PY_PID" | wc -l)
echo "[$PROXY_PY_PID] Main process: $OPEN_FILES_BY_MAIN"

pgrep -P "$PROXY_PY_PID" | while read -r acceptorPid; do
  OPEN_FILES_BY_ACCEPTOR=$(lsof -p "$acceptorPid" | wc -l)
  echo "[$acceptorPid] Acceptor process: $OPEN_FILES_BY_ACCEPTOR"

  pgrep -P "$acceptorPid" | while read -r threadlessPid; do
    OPEN_FILES_BY_THREADLESS=$(lsof -p "$threadlessPid" | wc -l)
    echo "  [$threadlessPid] Threadless process: $OPEN_FILES_BY_THREADLESS"
  done
done
