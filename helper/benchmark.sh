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
TIMEOUT=1
QPS=5000
CONCURRENCY=100
MILLION=100000
OPEN_FILE_LIMIT=65536
BACKLOG=OPEN_FILE_LIMIT
PID_FILE=/tmp/proxy.pid

ulimit -n $OPEN_FILE_LIMIT

# time python -m \
#     proxy \
#     --enable-web-server \
#     --plugin proxy.plugin.WebServerPlugin \
#     --backlog $BACKLOG \
#     --open-file-limit $OPEN_FILE_LIMIT \
#     --pid-file $PID_FILE \
#     --log-file /dev/null

PID=$(cat $PID_FILE)
if [[ -z "$PID" ]]; then
  echo "Either pid file doesn't exist or no pid found in the pid file"
  exit 1
fi
ADDR=$(lsof -Pan -p $PID -i | grep -v COMMAND | awk '{ print $9 }')

echo "CONCURRENCY: $CONCURRENCY workers, TOTAL REQUESTS: $MILLION req, QPS: $QPS req/sec, TIMEOUT: $TIMEOUT sec"
hey \
    -n $MILLION \
    -c $CONCURRENCY \
    -q $QPS \
    -t $TIMEOUT \
    http://$ADDR/http-route-example
