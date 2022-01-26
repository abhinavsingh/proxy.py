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

CERT_DIR=$2
if [[ -z "$CERT_DIR" ]]; then
  echo "CERT_DIR required as argument."
  exit 1
fi

PROXY_URL="127.0.0.1:$PROXY_PY_PORT"

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
        -x $PROXY_URL \
        --cacert $CERT_DIR/ca-cert.pem \
        http://$PROXY_URL/ 2>/dev/null
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
CMD="curl -v -x $PROXY_URL --cacert $CERT_DIR/ca-cert.pem http://httpbin.org/robots.txt"
RESPONSE=$($CMD 2> /dev/null)
verify_response "$RESPONSE" "$ROBOTS_RESPONSE"
VERIFIED1=$?

echo "[Test HTTPS Request via Proxy]"
CMD="curl -v -x $PROXY_URL --cacert $CERT_DIR/ca-cert.pem https://httpbin.org/robots.txt"
RESPONSE=$($CMD 2> /dev/null)
verify_response "$RESPONSE" "$ROBOTS_RESPONSE"
VERIFIED2=$?

echo "[Test Internal Web Server via Proxy]"
curl -v \
    -x $PROXY_URL \
    --cacert $CERT_DIR/ca-cert.pem \
    http://$PROXY_URL/
VERIFIED3=$?

SHASUM=sha256sum
if [ "$(uname)" = "Darwin" ];
then
    SHASUM="shasum -a 256"
fi

echo "[Test Download File Hash Verifies 1]"
touch downloaded.hash
echo "3d1921aab49d3464a712c1c1397b6babf8b461a9873268480aa8064da99441bc  -" > downloaded.hash
curl -vL \
    -o downloaded.whl \
    -x $PROXY_URL \
    --cacert $CERT_DIR/ca-cert.pem \
    https://files.pythonhosted.org/packages/88/78/e642316313b1cd6396e4b85471a316e003eff968f29773e95ea191ea1d08/proxy.py-2.4.0rc4-py3-none-any.whl#sha256=3d1921aab49d3464a712c1c1397b6babf8b461a9873268480aa8064da99441bc
cat downloaded.whl | $SHASUM -c downloaded.hash
VERIFIED4=$?
rm downloaded.whl downloaded.hash

echo "[Test Download File Hash Verifies 2]"
touch downloaded.hash
echo "077ce6014f7b40d03b47d1f1ca4b0fc8328a692bd284016f806ed0eaca390ad8  -" > downloaded.hash
curl -vL \
    -o downloaded.whl \
    -x $PROXY_URL \
    --cacert $CERT_DIR/ca-cert.pem \
    https://files.pythonhosted.org/packages/20/9a/e5d9ec41927401e41aea8af6d16e78b5e612bca4699d417f646a9610a076/Jinja2-3.0.3-py3-none-any.whl#sha256=077ce6014f7b40d03b47d1f1ca4b0fc8328a692bd284016f806ed0eaca390ad8
cat downloaded.whl | $SHASUM -c downloaded.hash
VERIFIED5=$?
rm downloaded.whl downloaded.hash

EXIT_CODE=$(( $VERIFIED1 || $VERIFIED2 || $VERIFIED3 || $VERIFIED4 || $VERIFIED5 ))
exit $EXIT_CODE
