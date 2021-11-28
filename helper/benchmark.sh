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
usage() {
  echo "Usage: ./helper/benchmark.sh"
  echo "You must run this script from proxy.py repo root."
}

DIRNAME=$(dirname "$0")
if [ "$DIRNAME" != "./helper" ]; then
  usage
  exit 1
fi

BASENAME=$(basename "$0")
if [ "$BASENAME" != "benchmark.sh" ]; then
  usage
  exit 1
fi

PWD=$(pwd)
if [ $(basename $PWD) != "proxy.py" ]; then
  usage
  exit 1
fi

TIMEOUT=1
QPS=8000
CONCURRENCY=100
TOTAL_REQUESTS=100000
OPEN_FILE_LIMIT=65536
BACKLOG=OPEN_FILE_LIMIT
PID_FILE=/tmp/proxy.pid

ulimit -n $OPEN_FILE_LIMIT

PID=$(cat $PID_FILE)
if [[ -z "$PID" ]]; then
  echo "Either pid file doesn't exist or no pid found in the pid file"
  exit 1
fi
ADDR=$(lsof -Pan -p $PID -i | grep -v COMMAND | awk '{ print $9 }')

PRE_RUN_OPEN_FILES=$(./helper/monitor_open_files.sh)

echo "CONCURRENCY: $CONCURRENCY workers, TOTAL REQUESTS: $TOTAL_REQUESTS req, QPS: $QPS req/sec, TIMEOUT: $TIMEOUT sec"
hey \
    -n $TOTAL_REQUESTS \
    -c $CONCURRENCY \
    -q $QPS \
    -t $TIMEOUT \
    http://$ADDR/http-route-example

POST_RUN_OPEN_FILES=$(./helper/monitor_open_files.sh)

echo $output

echo "Open files diff:"
diff <( echo "$PRE_RUN_OPEN_FILES" ) <( echo "$POST_RUN_OPEN_FILES" )

# while true; do netstat -ant | grep .8899 | awk '{print $6}' | sort | uniq -c | sort -n; sleep 1; done
