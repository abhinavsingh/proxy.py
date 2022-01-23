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

CURL="curl -v --connect-timeout 20 --max-time 120 --retry-connrefused --retry-delay 5 --retry 3"

PROXY_URL="http://localhost:$PROXY_PY_PORT"
CURL_EXTRA_FLAGS=""
USE_HTTPS=$2
if [[ ! -z "$USE_HTTPS" ]]; then
    PROXY_URL="https://localhost:$PROXY_PY_PORT"
    CURL_EXTRA_FLAGS=" -k --proxy-insecure "
    # For https instances we don't use internal https web server
    # See https://github.com/abhinavsingh/proxy.py/issues/994
    TEST_URL="http://google.com"
    USE_HTTPS=true
else
    TEST_URL="$PROXY_URL/http-route-example"
    USE_HTTPS=false
fi
REVERSE_PROXY_URL="$PROXY_URL/get"

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
CMD="$CURL $CURL_EXTRA_FLAGS -x $PROXY_URL $TEST_URL"
while true; do
    RESPONSE=$($CMD 2> /dev/null)
    if [[ $? == 0 ]]; then
        break
    fi
    echo "Waiting for web server to start accepting requests..."
    sleep 1
done

verify_response() {
    if [ "$1" == "" ];
    then
        echo "Empty response";
        return 1;
    else
        if [ "$1" == "$2" ];
        then
            echo "Ok";
            return 0;
        else
            echo "Invalid response: '$1', expected: '$2'";
            return 1;
        fi
    fi;
}

verify_contains() {
    if [ "$1" == "" ];
    then
        echo "Empty response";
        return 1;
    else
        if [[ "$1" == *"$2"* ]];
        then
            echo "Ok";
            return 0;
        else
            echo "Invalid response: '$1', expected: '$2'";
            return 1;
        fi
    fi;
}

# Check if proxy was started with integration
# testing web server plugin.  If detected, use
# internal web server for integration testing.

# If integration testing plugin is not found,
# detect if we have internet access.  If we do,
# then use httpbin.org for integration testing.
read -r -d '' ROBOTS_RESPONSE << EOM
User-agent: *
Disallow: /deny
EOM

echo "[Test HTTP Request via Proxy]"
CMD="$CURL $CURL_EXTRA_FLAGS -x $PROXY_URL http://httpbin.org/robots.txt"
RESPONSE=$($CMD 2> /dev/null)
verify_response "$RESPONSE" "$ROBOTS_RESPONSE"
VERIFIED1=$?

echo "[Test HTTPS Request via Proxy]"
CMD="$CURL $CURL_EXTRA_FLAGS -x $PROXY_URL https://httpbin.org/robots.txt"
RESPONSE=$($CMD 2> /dev/null)
verify_response "$RESPONSE" "$ROBOTS_RESPONSE"
VERIFIED2=$?

if $USE_HTTPS; then
    # See https://github.com/abhinavsingh/proxy.py/issues/994
    # for rationale
    VERIFIED3=0
else
    echo "[Test Internal Web Server via Proxy]"
    $CURL \
        $CURL_EXTRA_FLAGS \
        -x $PROXY_URL \
        "$PROXY_URL"
    VERIFIED3=$?
fi

SHASUM=sha256sum
if [ "$(uname)" = "Darwin" ];
then
    SHASUM="shasum -a 256"
fi

echo "[Test Download File Hash Verifies 1]"
touch downloaded1.hash
echo "3d1921aab49d3464a712c1c1397b6babf8b461a9873268480aa8064da99441bc  -" > downloaded1.hash
$CURL -L \
    $CURL_EXTRA_FLAGS \
    -o downloaded1.whl \
    -x $PROXY_URL \
    https://files.pythonhosted.org/packages/88/78/e642316313b1cd6396e4b85471a316e003eff968f29773e95ea191ea1d08/proxy.py-2.4.0rc4-py3-none-any.whl#sha256=3d1921aab49d3464a712c1c1397b6babf8b461a9873268480aa8064da99441bc
cat downloaded1.whl | $SHASUM -c downloaded1.hash
VERIFIED4=$?
rm downloaded1.whl downloaded1.hash

echo "[Test Download File Hash Verifies 2]"
touch downloaded2.hash
echo "077ce6014f7b40d03b47d1f1ca4b0fc8328a692bd284016f806ed0eaca390ad8  -" > downloaded2.hash
$CURL -L \
    $CURL_EXTRA_FLAGS \
    -o downloaded2.whl \
    -x $PROXY_URL \
    https://files.pythonhosted.org/packages/20/9a/e5d9ec41927401e41aea8af6d16e78b5e612bca4699d417f646a9610a076/Jinja2-3.0.3-py3-none-any.whl#sha256=077ce6014f7b40d03b47d1f1ca4b0fc8328a692bd284016f806ed0eaca390ad8
cat downloaded2.whl | $SHASUM -c downloaded2.hash
VERIFIED5=$?
rm downloaded2.whl downloaded2.hash

read -r -d '' REVERSE_PROXY_RESPONSE << EOM
"Host": "httpbin.org"
EOM

echo "[Test Reverse Proxy Plugin]"
CMD="$CURL $CURL_EXTRA_FLAGS $REVERSE_PROXY_URL"
RESPONSE=$($CMD 2> /dev/null)
verify_contains "$RESPONSE" "$REVERSE_PROXY_RESPONSE"
VERIFIED6=$?

EXIT_CODE=$(( $VERIFIED1 || $VERIFIED2 || $VERIFIED3 || $VERIFIED4 || $VERIFIED5 || $VERIFIED6))
exit $EXIT_CODE
