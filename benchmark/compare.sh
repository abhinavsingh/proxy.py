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
  echo "Usage: ./benchmark/compare.sh"
  echo "You must run this script from proxy.py repo root."
}

DIRNAME=$(dirname "$0")
if [ "$DIRNAME" != "./benchmark" ]; then
  usage
  exit 1
fi

BASENAME=$(basename "$0")
if [ "$BASENAME" != "compare.sh" ]; then
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
DURATION=1m
TOTAL_REQUESTS=100000
OPEN_FILE_LIMIT=65536
BACKLOG=OPEN_FILE_LIMIT

SERVER_HOST=127.0.0.1

AIOHTTP_PORT=8080
FLASK_PORT=8000
TORNADO_PORT=8888
PROXYPY_PORT=8899

ulimit -n $OPEN_FILE_LIMIT

echo "CONCURRENCY: $CONCURRENCY workers, QPS: $QPS req/sec, TOTAL DURATION: $DURATION, TIMEOUT: $TIMEOUT sec"

start_benchmark_stop() {
  python ./benchmark/$1/server.py > /dev/null 2>&1 &
  local SERVER_PID=$!
  echo "Server (pid:$SERVER_PID) running"
  sleep 1
  hey \
      -z $DURATION \
      -c $CONCURRENCY \
      -q $QPS \
      -t $TIMEOUT \
      http://127.0.0.1:$2/http-route-example
  kill -15 $SERVER_PID
  sleep 1
  kill -0 $SERVER_PID > /dev/null 2>&1
  local RUNNING=$?
  if [ "$RUNNING" == "1" ]; then
    echo "Server gracefully shutdown"
  fi
}

benchmark_proxy_py() {
  python -m proxy \
    --hostname 127.0.0.1 \
    --port $PROXYPY_PORT \
    --backlog 65536 \
    --open-file-limit 65536 \
    --enable-web-server \
    --plugin proxy.plugin.WebServerPlugin \
    --disable-http-proxy \
    --local-executor --log-file /dev/null > /dev/null 2>&1 &
  local SERVER_PID=$!
  echo "Server (pid:$SERVER_PID) running"
  sleep 1
  hey \
      -z $DURATION \
      -c $CONCURRENCY \
      -q $QPS \
      -t $TIMEOUT \
      http://127.0.0.1:$PROXYPY_PORT/http-route-example
  kill -15 $SERVER_PID
  sleep 1
  kill -0 $SERVER_PID > /dev/null 2>&1
  local RUNNING=$?
  if [ "$RUNNING" == "1" ]; then
    echo "Server gracefully shutdown"
  fi
}

echo "============================="
echo "Benchmarking Proxy.Py"
benchmark_proxy_py
echo "============================="

echo "============================="
echo "Benchmarking AIOHTTP"
start_benchmark_stop aiohttp $AIOHTTP_PORT
echo "============================="

echo "============================="
echo "Benchmarking Tornado"
start_benchmark_stop tornado $TORNADO_PORT
echo "============================="

echo "============================="
echo "Benchmarking Flask"
start_benchmark_stop flask $FLASK_PORT
echo "============================="
