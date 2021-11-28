#!/bin/bash

# TODO: Option to also shutdown proxy.py after
# integration testing is done.  At least on
# macOS and ubuntu, pkill and kill commands
# will do the job.
#
# For github action, we simply bank upon GitHub
# to clean up any background process including
# proxy.py

PROXY_PY_PORT=$1
if [[ -z "$PROXY_PY_PORT" ]]; then
  echo "PROXY_PY_PORT required as argument."
  exit 1
fi

# Wait for server to come up
WAIT_FOR_PROXY="lsof -i TCP:$PROXY_PY_PORT | wc -l | tr -d ' '"
while true; do
    if [[ $WAIT_FOR_PORT == 0 ]]; then
        echo "Waiting for proxy..."
        sleep 1
    else
        break
    fi
done

# Wait for http proxy and web server to start
while true; do
    curl -v \
        --max-time 1 \
        --connect-timeout 1 \
        -x 127.0.0.1:$PROXY_PY_PORT \
        http://127.0.0.1:$PROXY_PY_PORT/ 2>/dev/null
    if [[ $? == 0 ]]; then
        break
    fi
    echo "Waiting for web server to start accepting requests..."
    sleep 1
done

# Check if proxy was started with integration
# testing web server plugin.  If detected, use
# internal web server for integration testing.

# If integration testing plugin is not found,
# detect if we have internet access.  If we do,
# then use httpbin.org for integration testing.
curl -v \
    -x 127.0.0.1:$PROXY_PY_PORT \
    http://httpbin.org/get
if [[ $? != 0 ]]; then
    echo "http request failed"
    exit 1
fi

curl -v \
    -x 127.0.0.1:$PROXY_PY_PORT \
    https://httpbin.org/get
if [[ $? != 0 ]]; then
    echo "https request failed"
    exit 1
fi

curl -v \
    -x 127.0.0.1:$PROXY_PY_PORT \
    http://127.0.0.1:$PROXY_PY_PORT/
if [[ $? != 0 ]]; then
    echo "http request to built in webserver failed"
    exit 1
fi

exit 0
