#!/bin/bash

# TODO: Option to also shutdown proxy.py after
# integration testing is done.  Atleast on
# macOS and ubuntu, pkill and kill commands
# will do the job.
#
# For github action, we simply bank upon GitHub
# to clean up any background process including
# proxy.py

# Wait for server to come up
while true; do
    if [[ $(lsof -i TCP:8899 | wc -l | tr -d ' ') == 0 ]]; then
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
        -x localhost:8899 \
        http://localhost:8899/ 2>/dev/null
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
    -x localhost:8899 \
    http://httpbin.org/get
if [[ $? != 0 ]]; then
    echo "http request failed"
    exit 1
fi

curl -v \
    -x localhost:8899 \
    https://httpbin.org/get
if [[ $? != 0 ]]; then
    echo "https request failed"
    exit 1
fi

curl -v \
    -x localhost:8899 \
    http://localhost:8899/
if [[ $? != 0 ]]; then
    echo "http request to built in webserver failed"
    exit 1
fi

exit 0
