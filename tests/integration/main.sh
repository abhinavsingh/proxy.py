#!/bin/bash

# Wait for server to come up
while true; do
    if [[ $(lsof -i TCP:8899 | wc -l | tr -d ' ') == 0 ]]; then
        echo "Waiting for proxy..."
        sleep 1
    else
        break
    fi
done

# Check if proxy was started with integration
# testing web server plugin.  If detected, use
# internal web server for integration testing.

# If integration testing plugin is not found,
# detect if we have internet access.  If we do,
# then use httpbin.org for integration testing.

echo "OK"
exit 0
