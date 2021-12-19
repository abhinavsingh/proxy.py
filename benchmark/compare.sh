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

TIMEOUT=1sec
CONCURRENCY=100
DURATION=1m
TOTAL_REQUESTS=100000
OPEN_FILE_LIMIT=65536
BACKLOG=OPEN_FILE_LIMIT

SERVER_HOST=127.0.0.1

AIOHTTP_PORT=8080
TORNADO_PORT=8888
STARLETTE_PORT=8890
PROXYPY_PORT=8899
BLACKSHEEP_PORT=9000

ulimit -n $OPEN_FILE_LIMIT

echo "CONCURRENCY: $CONCURRENCY workers, DURATION: $DURATION, TIMEOUT: $TIMEOUT"

run_benchmark() {
  oha \
    --no-tui \
    --latency-correction \
    -z $DURATION \
    -c $CONCURRENCY \
    -t $TIMEOUT \
    http://127.0.0.1:$1/http-route-example
}

benchmark_lib() {
  python ./benchmark/_$1.py > /dev/null 2>&1 &
  local SERVER_PID=$!
  echo "Server (pid:$SERVER_PID) running"
  sleep 1
  run_benchmark $2
  kill -15 $SERVER_PID
  sleep 1
  kill -0 $SERVER_PID > /dev/null 2>&1
  local RUNNING=$?
  if [ "$RUNNING" == "1" ]; then
    echo "Server gracefully shutdown"
  fi
}

benchmark_asgi() {
  uvicorn \
    --port $1 \
    --backlog 65536 \
    $2 > /dev/null 2>&1 &
  local SERVER_PID=$!
  echo "Server (pid:$SERVER_PID) running"
  sleep 1
  run_benchmark $1
  kill -15 $SERVER_PID
  sleep 1
  kill -0 $SERVER_PID > /dev/null 2>&1
  local RUNNING=$?
  if [ "$RUNNING" == "1" ]; then
    echo "Server gracefully shutdown"
  fi
}

# echo "============================="
# echo "Benchmarking Proxy.Py"
# PYTHONPATH=. benchmark_lib proxy $PROXYPY_PORT
# echo "============================="

# echo "============================="
# echo "Benchmarking Blacksheep"
# benchmark_lib blacksheep $BLACKSHEEP_PORT
# echo "============================="

# echo "============================="
# echo "Benchmarking Starlette"
# benchmark_lib starlette $STARLETTE_PORT
# echo "============================="

# echo "============================="
# echo "Benchmarking AIOHTTP"
# benchmark_lib aiohttp $AIOHTTP_PORT
# echo "============================="

# echo "============================="
# echo "Benchmarking Tornado"
# benchmark_lib tornado $TORNADO_PORT
# echo "============================="
