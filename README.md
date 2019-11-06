[![Proxy.Py](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/ProxyPy.png)](https://github.com/abhinavsingh/proxy.py)

[![License](https://img.shields.io/github/license/abhinavsingh/proxy.py.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![PyPi Downloads](https://img.shields.io/pypi/dm/proxy.py.svg?color=green)](https://pypi.org/project/proxy.py/)
[![Docker Pulls](https://img.shields.io/docker/pulls/abhinavsingh/proxy.py?color=green)](https://hub.docker.com/r/abhinavsingh/proxy.py)
[![Build Status](https://travis-ci.org/abhinavsingh/proxy.py.svg?branch=develop)](https://travis-ci.org/abhinavsingh/proxy.py/)
[![No Dependencies](https://img.shields.io/static/v1?label=dependencies&message=none&color=green)](https://github.com/abhinavsingh/proxy.py)
[![Coverage](https://codecov.io/gh/abhinavsingh/proxy.py/branch/develop/graph/badge.svg)](https://codecov.io/gh/abhinavsingh/proxy.py)

[![Tested With MacOS](https://img.shields.io/static/v1?label=tested%20with&message=mac%20OS%20%F0%9F%92%BB&color=brightgreen)](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)
[![Tested With Ubuntu](https://img.shields.io/static/v1?label=tested%20with&message=Ubuntu%20%F0%9F%96%A5&color=brightgreen)](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)
[![Tested With Windows](https://img.shields.io/static/v1?label=tested%20with&message=Windows%20%F0%9F%92%BB&color=brightgreen)](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)
[![Tested With Android](https://img.shields.io/static/v1?label=tested%20with&message=Android%20%F0%9F%93%B1&color=brightgreen)](https://www.android.com/)
[![Tested With Android Emulator](https://img.shields.io/static/v1?label=tested%20with&message=Android%20Emulator%20%F0%9F%93%B1&color=brightgreen)](https://developer.android.com/studio/run/emulator-networking.html#proxy)
[![Tested With iOS](https://img.shields.io/static/v1?label=tested%20with&message=iOS%20%F0%9F%93%B1&color=brightgreen)](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)
[![Tested With iOS Simulator](https://img.shields.io/static/v1?label=tested%20with&message=iOS%20Simulator%20%F0%9F%93%B1&color=brightgreen)](https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/Introduction/Introduction.html)

[![Maintenance](https://img.shields.io/static/v1?label=maintained%3F&message=yes&color=green)](https://gitHub.com/abhinavsingh/proxy.py/graphs/commit-activity)
[![Ask Me Anything](https://img.shields.io/static/v1?label=need%20help%3F&message=ask&color=green)](https://twitter.com/imoracle)
[![Contributions Welcome](https://img.shields.io/static/v1?label=contributions&message=welcome%20%F0%9F%91%8D&color=green)](https://github.com/abhinavsingh/proxy.py/issues)
[![Gitter](https://badges.gitter.im/proxy-py/community.svg)](https://gitter.im/proxy-py/community)

[![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/)
[![Checked with mypy](https://img.shields.io/static/v1?label=mypy&message=checked&color=blue)](http://mypy-lang.org/)

[![Become a Backer](https://opencollective.com/proxypy/tiers/backer.svg?avatarHeight=36)](https://opencollective.com/proxypy)

Table of Contents
=================

* [Features](#features)
* [Install](#install)
    * [Stable version](#stable-version)
    * [Development version](#development-version)
* [Start proxy.py](#start-proxypy)
    * [From command line when installed using PIP](#from-command-line-when-installed-using-pip)
        * [Run it](#run-it)
        * [Reading logs](#reading-logs)
        * [Enable DEBUG logging](#enable-debug-logging)
    * [From command line using repo source](#from-command-line-using-repo-source)
    * [Docker Image](#docker-image)
        * [Stable version](#stable-version-from-docker-hub)
        * [Development version](#build-development-version-locally)
        * [Customize Startup Flags](#customize-startup-flags)
* [Plugin Examples](#plugin-examples)
    * [ShortLinkPlugin](#shortlinkplugin)
    * [ModifyPostDataPlugin](#modifypostdataplugin)
    * [MockRestApiPlugin](#mockrestapiplugin)
    * [RedirectToCustomServerPlugin](#redirecttocustomserverplugin)
    * [FilterByUpstreamHostPlugin](#filterbyupstreamhostplugin)
    * [CacheResponsesPlugin](#cacheresponsesplugin)
    * [ManInTheMiddlePlugin](#maninthemiddleplugin)
    * [Plugin Ordering](#plugin-ordering)
* [End-to-End Encryption](#end-to-end-encryption)
* [TLS Interception](#tls-interception)
* [Embed proxy.py](#embed-proxypy)
    * [Blocking Mode](#blocking-mode)
    * [Non-blocking Mode](#non-blocking-mode)
* [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
    * [Everything is a plugin](#everything-is-a-plugin)
    * [Internal Architecture](#internal-architecture)
    * [Internal Documentation](#internal-documentation)
    * [Sending a Pull Request](#sending-a-pull-request)
    * [Utilities](#utilities)
        * [TCP](#tcp-sockets)
            * [new_socket_connection](#new_socket_connection)
            * [socket_connection](#socket_connection)
        * [Http](#http-client)
            * [build_http_request](#build_http_request)
            * [build_http_response](#build_http_response)
        * [Websocket](#websocket)
            * [WebsocketFrame](#websocketframe)
            * [WebsocketClient](#websocketclient)
* [Frequently Asked Questions](#frequently-asked-questions)
    * [SyntaxError: invalid syntax](#syntaxerror-invalid-syntax)
    * [Unable to connect with proxy.py from remote host](#unable-to-connect-with-proxypy-from-remote-host)
    * [Basic auth not working with a browser](#basic-auth-not-working-with-a-browser)
    * [Docker image not working on MacOS](#docker-image-not-working-on-macos)
    * [Unable to load custom plugins](#unable-to-load-custom-plugins)
    * [ValueError: filedescriptor out of range in select](#valueerror-filedescriptor-out-of-range-in-select)
* [Flags](#flags)
* [Changelog](#changelog)

Features
========

- Fast & Scalable
    - Scales by using all available cores on the system
    - Threadless executions using coroutine
    - Made to handle `tens-of-thousands` connections / sec
        ```
        # On Macbook Pro 2015 / 2.8 GHz Intel Core i7
        $ hey -n 10000 -c 100 http://localhost:8899/

        Summary:
          Total:	0.6157 secs
          Slowest:	0.1049 secs
          Fastest:	0.0007 secs
          Average:	0.0055 secs
          Requests/sec:	16240.5444

          Total data:	800000 bytes
          Size/request:	80 bytes

        Response time histogram:
          0.001 [1]     |
          0.011 [9565]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
          0.022 [332]	|■
        ```
- Lightweight
    - Uses only `~5-20MB` RAM
    - No external dependency other than standard Python library
- Programmable
    - Optionally enable builtin Web Server
    - Customize proxy and http routing via [plugins](https://github.com/abhinavsingh/proxy.py/blob/develop/plugin_examples)
    - Enable plugin using command line option e.g. `--plugins plugin_examples/cache_responses.CacheResponsesPlugin`
    - Plugin API is currently in development phase, expect breaking changes.
- Realtime Dashboard
    - Optionally enable bundled dashboard.
        - Available at `http://localhost:8899/dashboard`.
    - Inspect, Monitor, Control and Configure `proxy.py` at runtime.
    - Extend dashboard using plugins.
    - Dashboard is currently in development phase, expect breaking changes.
- Secure
    - Enable end-to-end encryption between clients and `proxy.py` using TLS
    - See [End-to-End Encryption](#end-to-end-encryption)
- Man-In-The-Middle
    - Can decrypt TLS traffic between clients and upstream servers
    - See [TLS Encryption](#tls-interception)
- Supported proxy protocols
    - `http`
    - `https`
    - `http2`
    - `websockets`
- Optimized for large file uploads and downloads
- IPv4 and IPv6 support
- Basic authentication support
- Can serve a [PAC (Proxy Auto-configuration)](https://en.wikipedia.org/wiki/Proxy_auto-config) file
    - See `--pac-file` and `--pac-file-url-path` flags

Install
=======

## Stable version

Install from `PyPi`

	$ pip install --upgrade proxy.py

or from GitHub `master` branch

    $ pip install git+https://github.com/abhinavsingh/proxy.py.git@master

## Development version

    $ pip install git+https://github.com/abhinavsingh/proxy.py.git@develop

For `Docker` installation see [Docker Image](#docker-image).

Start proxy.py
==============

## From command line when installed using PIP

When `proxy.py` is installed using `pip`,
an executable named `proxy` is added under your `$PATH`.

#### Run it

Simply type `proxy` on command line to start it with default configuration.

```
$ proxy
...[redacted]... - Loaded plugin proxy.http_proxy.HttpProxyPlugin
...[redacted]... - Starting 8 workers
...[redacted]... - Started server on ::1:8899
```

#### Reading logs

Things to notice from above logs:

- `Loaded plugin` - `proxy.py` will load `proxy.http.proxy.HttpProxyPlugin` by default.
  As name suggests, this core plugin adds `http(s)` proxy server capabilities to `proxy.py`

- `Started N workers` - Use `--num-workers` flag to customize number of worker processes. 
  By default, `proxy.py` will start as many workers as there are CPU cores on the machine.

- `Started server on ::1:8899` - By default, `proxy.py` listens on IPv6 `::1`, which 
  is equivalent of IPv4 `127.0.0.1`.  If you want to access `proxy.py` externally, 
  use `--hostname ::` or `--hostname 0.0.0.0` or bind to any other interface available 
  on your machine.

- `Port 8899` - Use `--port` flag to customize default TCP port.

#### Enable DEBUG logging

All the logs above are `INFO` level logs, default `--log-level` for `proxy.py`. 

Lets start `proxy.py` with `DEBUG` level logging:

```
$ proxy --log-level d
...[redacted]... - Open file descriptor soft limit set to 1024
...[redacted]... - Loaded plugin proxy.http_proxy.HttpProxyPlugin
...[redacted]... - Started 8 workers
...[redacted]... - Started server on ::1:8899
```

As we can see, before starting up:

- `proxy.py` also tried to set open file limit `ulimit` on the system.
- Default value for `--open-file-limit` used is `1024`.
- `--open-file-limit` flag is a no-op on `Windows` operating systems.

See [flags](#flags) for full list of available configuration options.

## From command line using repo source

If you are trying to run `proxy.py` from source code,
there is no binary file named `proxy` in the source code.

To start `proxy.py` from source code follow these instructions:

- Clone repo

    ```
    $ git clone https://github.com/abhinavsingh/proxy.py.git
    $ cd proxy.py
    ```

- Create a Python 3 virtual env

    ```
    $ python3 -m venv venv
    $ source venv/bin/activate
    ```

- Install deps

    ```
    $ pip install -r requirements.txt
    $ pip install -r requirements-testing.txt
    ```

- Run tests

    ```
    $ make
    ```

- Run proxy.py

    ```
    $ python -m proxy
    ```

Also see [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
if you plan to work with `proxy.py` source code.

## Docker image

#### Stable Version from Docker Hub

    $ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest

#### Build Development Version Locally

    $ git clone https://github.com/abhinavsingh/proxy.py.git
    $ cd proxy.py
    $ make container
    $ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest

#### Customize startup flags

By default `docker` binary is started with IPv4 networking flags:

    --hostname 0.0.0.0 --port 8899

To override input flags, start docker image as follows.
For example, to check `proxy.py` version within Docker image:

    $ docker run -it \
        -p 8899:8899 \
        --rm abhinavsingh/proxy.py:latest \
        -v

[![WARNING](https://img.shields.io/static/v1?label=MacOS&message=warning&color=red)](https://github.com/moby/vpnkit/issues/469)
`docker` image is currently broken on `macOS` due to incompatibility with [vpnkit](https://github.com/moby/vpnkit/issues/469).

Plugin Examples
===============

See [plugin_examples](https://github.com/abhinavsingh/proxy.py/tree/develop/plugin_examples) for full code.

All the examples below also works with `https` traffic but require additional flags and certificate generation. 
See [TLS Interception](#tls-interception).

## ShortLinkPlugin

Add support for short links in your favorite browsers / applications.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/shortlink.ShortLinkPlugin
```

Now you can speed up your daily browsing experience by visiting your
favorite website using single character domain names :).  This works
across all browsers.

Following short links are enabled by default:

Short Link | Destination URL
:--------: | :---------------:
a/ | amazon.com
i/ | instagram.com
l/ | linkedin.com
f/ | facebook.com
g/ | google.com
t/ | twitter.com
w/ | web.whatsapp.com
y/ | youtube.com
proxy/ | localhost:8899

## ModifyPostDataPlugin

Modifies POST request body before sending request to upstream server.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/modify_post_data.ModifyPostDataPlugin
```

By default plugin replaces POST body content with hardcoded `b'{"key": "modified"}'`
and enforced `Content-Type: application/json`.

Verify the same using `curl -x localhost:8899 -d '{"key": "value"}' http://httpbin.org/post`

```
{
  "args": {},
  "data": "{\"key\": \"modified\"}",
  "files": {},
  "form": {},
  "headers": {
    "Accept": "*/*",
    "Content-Length": "19",
    "Content-Type": "application/json",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "json": {
    "key": "modified"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/post"
}
```

Note following from the response above:

1. POST data was modified `"data": "{\"key\": \"modified\"}"`.
   Original `curl` command data was `{"key": "value"}`.
2. Our `curl` command did not add any `Content-Type` header,
   but our plugin did add one `"Content-Type": "application/json"`.
   Same can also be verified by looking at `json` field in the output above:
   ```
   "json": {
    "key": "modified"
   },
   ```
3. Our plugin also added a `Content-Length` header to match length
   of modified body.

## MockRestApiPlugin

Mock responses for your server REST API.
Use to test and develop client side applications
without need of an actual upstream REST API server.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/mock_rest_api.ProposedRestApiPlugin
```

Verify mock API response using `curl -x localhost:8899 http://api.example.com/v1/users/`

```
{"count": 2, "next": null, "previous": null, "results": [{"email": "you@example.com", "groups": [], "url": "api.example.com/v1/users/1/", "username": "admin"}, {"email": "someone@example.com", "groups": [], "url": "api.example.com/v1/users/2/", "username": "admin"}]}
```

Verify the same by inspecting `proxy.py` logs:

```
2019-09-27 12:44:02,212 - INFO - pid:7077 - access_log:1210 - ::1:64792 - GET None:None/v1/users/ - None None - 0 byte
```

Access log shows `None:None` as server `ip:port`.  `None` simply means that
the server connection was never made, since response was returned by our plugin.

Now modify `ProposedRestApiPlugin` to returns REST API mock 
responses as expected by your clients.

## RedirectToCustomServerPlugin

Redirects all incoming `http` requests to custom web server. 
By default, it redirects client requests to inbuilt web server, 
also running on `8899` port.

Start `proxy.py` and enable inbuilt web server:

```
$ proxy \
    --enable-web-server \
    --plugins plugin_examples/redirect_to_custom_server.RedirectToCustomServerPlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`

```
... [redacted] ...
< HTTP/1.1 404 NOT FOUND
< Server: proxy.py v1.0.0
< Connection: Close
< 
* Closing connection 0
```

Above `404` response was returned from `proxy.py` web server. 

Verify the same by inspecting the logs for `proxy.py`. 
Along with the proxy request log, you must also see a http web server request log.

```
2019-09-24 19:09:33,602 - INFO - pid:49996 - access_log:1241 - ::1:49525 - GET /
2019-09-24 19:09:33,603 - INFO - pid:49995 - access_log:1157 - ::1:49524 - GET localhost:8899/ - 404 NOT FOUND - 70 bytes
```

## FilterByUpstreamHostPlugin

Drops traffic by inspecting upstream host. 
By default, plugin drops traffic for `google.com` and `www.google.com`.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/filter_by_upstream.FilterByUpstreamHostPlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`:

```
... [redacted] ...
< HTTP/1.1 418 I'm a tea pot
< Proxy-agent: proxy.py v1.0.0
* no chunk, no close, no size. Assume close to signal end
< 
* Closing connection 0
```

Above `418 I'm a tea pot` is sent by our plugin.

Verify the same by inspecting logs for `proxy.py`:

```
2019-09-24 19:21:37,893 - ERROR - pid:50074 - handle_readables:1347 - HttpProtocolException type raised
Traceback (most recent call last):
... [redacted] ...
2019-09-24 19:21:37,897 - INFO - pid:50074 - access_log:1157 - ::1:49911 - GET None:None/ - None None - 0 bytes
```

## CacheResponsesPlugin

Caches Upstream Server Responses.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/cache_responses.CacheResponsesPlugin
```

Verify using `curl -v -x localhost:8899 http://httpbin.org/get`:

```
... [redacted] ...
< HTTP/1.1 200 OK
< Access-Control-Allow-Credentials: true
< Access-Control-Allow-Origin: *
< Content-Type: application/json
< Date: Wed, 25 Sep 2019 02:24:25 GMT
< Referrer-Policy: no-referrer-when-downgrade
< Server: nginx
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1; mode=block
< Content-Length: 202
< Connection: keep-alive
< 
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/get"
}
* Connection #0 to host localhost left intact
```

Get path to the cache file from `proxy.py` logs:

```
... [redacted] ... - GET httpbin.org:80/get - 200 OK - 556 bytes
... [redacted] ... - Cached response at /var/folders/k9/x93q0_xn1ls9zy76m2mf2k_00000gn/T/httpbin.org-1569378301.407512.txt
```

Verify contents of the cache file `cat /path/to/your/cache/httpbin.org.txt`

```
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Content-Type: application/json
Date: Wed, 25 Sep 2019 02:24:25 GMT
Referrer-Policy: no-referrer-when-downgrade
Server: nginx
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Length: 202
Connection: keep-alive

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/get"
}
```

## ManInTheMiddlePlugin

Modifies upstream server responses.

Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/man_in_the_middle.ManInTheMiddlePlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`:

```
... [redacted] ...
< HTTP/1.1 200 OK
< Content-Length: 28
< 
* Connection #0 to host localhost left intact
Hello from man in the middle
```

Response body `Hello from man in the middle` is sent by our plugin.

## Plugin Ordering

When using multiple plugins, depending upon plugin functionality, 
it might be worth considering the order in which plugins are passed 
on the command line.

Plugins are called in the same order as they are passed. Example, 
say we are using both `FilterByUpstreamHostPlugin` and 
`RedirectToCustomServerPlugin`. Idea is to drop all incoming `http` 
requests for `google.com` and `www.google.com` and redirect other 
`http` requests to our inbuilt web server.

Hence, in this scenario it is important to use 
`FilterByUpstreamHostPlugin` before `RedirectToCustomServerPlugin`. 
If we enable `RedirectToCustomServerPlugin` before `FilterByUpstreamHostPlugin`,
`google` requests will also get redirected to inbuilt web server, 
instead of being dropped.

End-to-End Encryption
=====================

By default, `proxy.py` uses `http` protocol for communication with clients e.g. `curl`, `browser`. 
For enabling end-to-end encrypting using `tls` / `https` first generate certificates:

```
make https-certificates
```

Start `proxy.py` as:

```
$ proxy \
    --cert-file https-cert.pem \
    --key-file https-key.pem
```

Verify using `curl -x https://localhost:8899 --proxy-cacert https-cert.pem https://httpbin.org/get`:

```
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/get"
}
```

TLS Interception
=================

By default, `proxy.py` will not decrypt `https` traffic between client and server. 
To enable TLS interception first generate CA certificates:

```
make ca-certificates
```

Lets also enable `CacheResponsePlugin` so that we can verify decrypted
response from the server. Start `proxy.py` as:

```
$ proxy \
    --plugins plugin_examples/cache_responses.CacheResponsesPlugin \
    --ca-key-file ca-key.pem \
    --ca-cert-file ca-cert.pem \
    --ca-signing-key-file ca-signing-key.pem
```

Verify using `curl -v -x localhost:8899 --cacert ca-cert.pem https://httpbin.org/get`

```
*  issuer: C=US; ST=CA; L=SanFrancisco; O=proxy.py; OU=CA; CN=Proxy PY CA; emailAddress=proxyca@mailserver.com
*  SSL certificate verify ok.
> GET /get HTTP/1.1
... [redacted] ...
< Connection: keep-alive
< 
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/get"
}
```

The `issuer` line confirms that response was intercepted.

Also verify the contents of cached response file.  Get path to the cache
file from `proxy.py` logs.

`$ cat /path/to/your/tmp/directory/httpbin.org-1569452863.924174.txt`

```
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: *
Content-Type: application/json
Date: Wed, 25 Sep 2019 23:07:05 GMT
Referrer-Policy: no-referrer-when-downgrade
Server: nginx
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Length: 202
Connection: keep-alive

{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://httpbin.org/get"
}
```

Viola!!!  If you remove CA flags, encrypted data will be found in the
cached file instead of plain text.

Now use CA flags with other 
[plugin examples](#plugin-examples) to see them work with `https` traffic.

Embed proxy.py
==============

## Blocking Mode

Start `proxy.py` in embedded mode by using `main` method:

```
from proxy.main import main

if __name__ == '__main__':
  main([])
```

or, to start with arguments:

```
from proxy.main import main

if __name__ == '__main__':
  main([
    '--hostname', '::1',
    '--port', '8899'
  ])
```

Note that:

1. Calling `main` is simply equivalent to starting `proxy.py` from command line.
2. `main` will block until `proxy.py` shuts down.

## Non-blocking Mode

Start `proxy.py` in embedded mode by using `start` method:

```
from proxy.main import start

if __name__ == '__main__':
  with start([]):
    # ... your logic here ...
```

Note that:

1. `start` is simply a context manager.
2. Is similar to calling `main` except `start` won't block.
3. It automatically shut down `proxy.py`.

Plugin Developer and Contributor Guide
======================================

Contributors must start `proxy.py` from source to verify and develop new features / fixes.

See [Run proxy.py from command line using repo source](#from-command-line-using-repo-source) for details.

## Everything is a plugin

As you might have guessed by now, in `proxy.py` everything is a plugin.

- We enabled proxy server plugins using `--plugins` flag.
  All the [plugin examples](#plugin-examples) were implementing 
  `HttpProxyBasePlugin`.  See documentation of 
  [HttpProxyBasePlugin](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L894-L938) 
  for available lifecycle hooks. Use `HttpProxyBasePlugin` to modify 
  behavior of http(s) proxy protocol between client and upstream server. 
  Example, [FilterByUpstreamHostPlugin](#filterbyupstreamhostplugin).

- We also enabled inbuilt web server using `--enable-web-server`. 
  Inbuilt web server implements `HttpProtocolHandlerPlugin` plugin. 
  See documentation of [HttpProtocolHandlerPlugin](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L793-L850) 
  for available lifecycle hooks. Use `HttpProtocolHandlerPlugin` to add 
  new features for http(s) clients. Example, 
  [HttpWebServerPlugin](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L1185-L1260).

- There also is a `--disable-http-proxy` flag. It disables inbuilt proxy server.
  Use this flag with `--enable-web-server` flag to run `proxy.py` as a programmable
  http(s) server. [HttpProxyPlugin](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L941-L1182) 
  also implements `HttpProtocolHandlerPlugin`.

## Internal Architecture

- [HttpProtocolHandler](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L1263-L1440) 
thread is started with the accepted [TcpClientConnection](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L230-L237).
`HttpProtocolHandler` is responsible for parsing incoming client request and invoking
`HttpProtocolHandlerPlugin` lifecycle hooks.

- `HttpProxyPlugin` which implements `HttpProtocolHandlerPlugin` also has its own plugin 
mechanism. Its responsibility is to establish connection between client and 
upstream [TcpServerConnection](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L204-L227)
and invoke `HttpProxyBasePlugin` lifecycle hooks.

- `HttpProtocolHandler` threads are started by [Acceptor](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L424-L472) 
  processes.

- `--num-workers` `Acceptor` processes are started by 
  [AcceptorPool](https://github.com/abhinavsingh/proxy.py/blob/b03629fa0df1595eb4995427bc601063be7fdca9/proxy.py#L368-L421) 
  on start-up.

- `AcceptorPool` listens on server socket and pass the handler to `Acceptor` processes.
  Workers are responsible for accepting new client connections and starting
  `HttpProtocolHandler` thread.

## Sending a Pull Request

Install dependencies for local development testing:

`$ pip install -r requirements-testing.txt`

Every pull request goes through set of tests which must pass:

- `mypy`: Run `make lint` locally for compliance check. 
  Fix all warnings and errors before sending out a PR.

- `coverage`: Run `make coverage` locally for coverage report.
  Its ideal to add tests for any critical change. Depending upon
  the change, it's ok if test coverage falls by `<0.5%`.

- `formatting`: Run `make autopep8` locally to format the code in-place.
  `autopep8` is run with `--aggresive` flag.  Sometimes it _may_ result in
  weird formatting.  But let's stick to one consistent formatting tool.
  I am open to flag changes for `autopep8`.

## Utilities

## TCP Sockets

#### new_socket_connection

Attempts to create an IPv4 connection, then IPv6 and
finally a dual stack connection to provided address.

```
>>> conn = new_socket_connection(('httpbin.org', 80))
>>> ...[ use connection ]...
>>> conn.close()
```

#### socket_connection

`socket_connection` is a convenient decorator + context manager
around `new_socket_connection` which ensures `conn.close` is implicit.

As a context manager:

```
>>> with socket_connection(('httpbin.org', 80)) as conn:
>>>   ... [ use connection ] ...
```

As a decorator:

```
>>> @socket_connection(('httpbin.org', 80))
>>> def my_api_call(conn, *args, **kwargs):
>>>   ... [ use connection ] ...
```

## Http Client

#### build_http_request

##### Generate HTTP GET request

```
>>> build_http_request(b'GET', b'/')
b'GET / HTTP/1.1\r\n\r\n'
>>>
```

##### Generate HTTP GET request with headers

```
>>> build_http_request(b'GET', b'/', 
        headers={b'Connection': b'close'})
b'GET / HTTP/1.1\r\nConnection: close\r\n\r\n'
>>>
```

##### Generate HTTP POST request with headers and body

```
>>> import json
>>> build_http_request(b'POST', b'/form', 
        headers={b'Content-type': b'application/json'}, 
        body=proxy.bytes_(json.dumps({'email': 'hello@world.com'})))
    b'POST /form HTTP/1.1\r\nContent-type: application/json\r\n\r\n{"email": "hello@world.com"}'
```

#### build_http_response

TODO

## Websocket

#### WebsocketFrame

TODO

#### WebsocketClient

TODO

## Internal Documentation

Browse through internal class hierarchy and documentation using `pydoc3`.
Example:

```
$ pydoc3 proxy

PACKAGE CONTENTS
    __main__
    common (package)
    core (package)
    http (package)
    main

FILE
    /Users/abhinav/Dev/proxy.py/proxy/__init__.py
```

Frequently Asked Questions
==========================

## SyntaxError: invalid syntax

Make sure you are using `Python 3`. Verify the version before running `proxy.py`:

`$ python --version`

## Unable to connect with proxy.py from remote host

Make sure `proxy.py` is listening on correct network interface.
Try following flags:

- For IPv6 `--hostname ::`
- For IPv4 `--hostname 0.0.0.0`

## Basic auth not working with a browser

Most likely it's a browser integration issue with system keychain.

- First verify that basic auth is working using `curl`

    `curl -v -x username:password@localhost:8899 https://httpbin.org/get`

- See [this thread](https://github.com/abhinavsingh/proxy.py/issues/89#issuecomment-534845710)
  for further details.

## Docker image not working on macOS

It's a compatibility issue with `vpnkit`.

See [moby/vpnkit exhausts docker resources](https://github.com/abhinavsingh/proxy.py/issues/43)
and [Connection refused: The proxy could not connect](https://github.com/moby/vpnkit/issues/469)
for some background.

## Unable to load custom plugins

Make sure your plugin modules are discoverable by adding them to `PYTHONPATH`.  Example:

`PYTHONPATH=/path/to/my/app proxy --plugins my_app.proxyPlugin`

```
...[redacted]... - Loaded plugin proxy.HttpProxyPlugin
...[redacted]... - Loaded plugin my_app.proxyPlugin
```

or, make sure to pass fully-qualified path as parameter, e.g.

`proxy --plugins /path/to/my/app/my_app.proxyPlugin`

## GCE log viewer integration for proxy.py

A starter [fluentd.conf](https://github.com/abhinavsingh/proxy.py/blob/develop/fluentd.conf)
template is available.

1. Copy this configuration file as `proxy.py.conf` under
   `/etc/google-fluentd/config.d/`

2. Update `path` field to log file path as used with `--log-file` flag.
   By default `/tmp/proxy.log` path is tailed.

3. Reload `google-fluentd`:

   `sudo service google-fluentd restart`

Now `proxy.py` logs can be browsed using
[GCE log viewer](https://console.cloud.google.com/logs/viewer).

## ValueError: filedescriptor out of range in select

`proxy.py` is made to handle thousands of connections per second
without any socket leaks.

1. Make use of `--open-file-limit` flag to customize `ulimit -n`.
    - To set a value upper than the hard limit, run as root.
2. Make sure to adjust `--backlog` flag for higher concurrency.

If nothing helps, [open an issue](https://github.com/abhinavsingh/proxy.py/issues/new)
with `requests per second` sent and output of following debug script:

```
$ ./helper/monitor_open_files.sh <proxy-py-pid>
```

Flags
=====

```
❯ proxy -h
usage: proxy [-h] [--backlog BACKLOG] [--basic-auth BASIC_AUTH]
             [--ca-key-file CA_KEY_FILE] [--ca-cert-dir CA_CERT_DIR]
             [--ca-cert-file CA_CERT_FILE]
             [--ca-signing-key-file CA_SIGNING_KEY_FILE]
             [--cert-file CERT_FILE]
             [--client-recvbuf-size CLIENT_RECVBUF_SIZE]
             [--devtools-ws-path DEVTOOLS_WS_PATH]
             [--disable-headers DISABLE_HEADERS] [--disable-http-proxy]
             [--enable-devtools] [--enable-events] [--enable-static-server]
             [--enable-web-server] [--hostname HOSTNAME] [--key-file KEY_FILE]
             [--log-level LOG_LEVEL] [--log-file LOG_FILE]
             [--log-format LOG_FORMAT] [--num-workers NUM_WORKERS]
             [--open-file-limit OPEN_FILE_LIMIT] [--pac-file PAC_FILE]
             [--pac-file-url-path PAC_FILE_URL_PATH] [--pid-file PID_FILE]
             [--plugins PLUGINS] [--port PORT]
             [--server-recvbuf-size SERVER_RECVBUF_SIZE]
             [--static-server-dir STATIC_SERVER_DIR] [--threadless]
             [--timeout TIMEOUT] [--version]

proxy.py v2.0.0

optional arguments:
  -h, --help            show this help message and exit
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --ca-key-file CA_KEY_FILE
                        Default: None. CA key to use for signing dynamically
                        generated HTTPS certificates. If used, must also pass
                        --ca-cert-file and --ca-signing-key-file
  --ca-cert-dir CA_CERT_DIR
                        Default: ~/.proxy.py. Directory to store dynamically
                        generated certificates. Also see --ca-key-file, --ca-
                        cert-file and --ca-signing-key-file
  --ca-cert-file CA_CERT_FILE
                        Default: None. Signing certificate to use for signing
                        dynamically generated HTTPS certificates. If used,
                        must also pass --ca-key-file and --ca-signing-key-file
  --ca-signing-key-file CA_SIGNING_KEY_FILE
                        Default: None. CA signing key to use for dynamic
                        generation of HTTPS certificates. If used, must also
                        pass --ca-key-file and --ca-cert-file
  --cert-file CERT_FILE
                        Default: None. Server certificate to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --key-file.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --devtools-ws-path DEVTOOLS_WS_PATH
                        Default: /devtools. Only applicable if --enable-
                        devtools is used.
  --disable-headers DISABLE_HEADERS
                        Default: None. Comma separated list of headers to
                        remove before dispatching client request to upstream
                        server.
  --disable-http-proxy  Default: False. Whether to disable
                        proxy.HttpProxyPlugin.
  --enable-devtools     Default: False. Enables integration with Chrome
                        Devtool Frontend.
  --enable-events       Default: False. Enables core to dispatch lifecycle
                        events. Plugins can be used to subscribe for core
                        events.
  --enable-static-server
                        Default: False. Enable inbuilt static file server.
                        Optionally, also use --static-server-dir to serve
                        static content from custom directory. By default,
                        static file server serves from public folder.
  --enable-web-server   Default: False. Whether to enable
                        proxy.HttpWebServerPlugin.
  --hostname HOSTNAME   Default: ::1. Server IP address.
  --key-file KEY_FILE   Default: None. Server key file to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --cert-file.
  --log-level LOG_LEVEL
                        Valid options: DEBUG, INFO (default), WARNING, ERROR,
                        CRITICAL. Both upper and lowercase values are allowed.
                        You may also simply use the leading character e.g.
                        --log-level d
  --log-file LOG_FILE   Default: sys.stdout. Log file destination.
  --log-format LOG_FORMAT
                        Log format for Python logger.
  --num-workers NUM_WORKERS
                        Defaults to number of CPU cores.
  --open-file-limit OPEN_FILE_LIMIT
                        Default: 1024. Maximum number of files (TCP
                        connections) that proxy.py can open concurrently.
  --pac-file PAC_FILE   A file (Proxy Auto Configuration) or string to serve
                        when the server receives a direct file request. Using
                        this option enables proxy.HttpWebServerPlugin.
  --pac-file-url-path PAC_FILE_URL_PATH
                        Default: /. Web server path to serve the PAC file.
  --pid-file PID_FILE   Default: None. Save parent process ID to a file.
  --plugins PLUGINS     Comma separated plugins
  --port PORT           Default: 8899. Server port.
  --server-recvbuf-size SERVER_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the server in a single recv() operation. Bump this
                        value for faster downloads at the expense of increased
                        RAM.
  --static-server-dir STATIC_SERVER_DIR
                        Default: "public" folder in directory where proxy.py
                        is placed. This option is only applicable when static
                        server is also enabled. See --enable-static-server.
  --threadless          Default: False. When disabled a new thread is spawned
                        to handle each client connection.
  --timeout TIMEOUT     Default: 10. Number of seconds after which an inactive
                        connection must be dropped. Inactivity is defined by
                        no data sent or received by the client.
  --version, -v         Prints proxy.py version.

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```

Changelog
=========

- `v2.x`
    - No longer ~~a single file module~~.
    - Added support for threadless execution.
    - Added dashboard app.
- `v1.x`
    - `Python3` only.
        - Deprecated support for ~~Python 2.x~~.
    - Added support multi core accept.
    - Added plugin support.
- `v0.x`
    - Single file.
    - Single threaded server.

For detailed changelog refer either to release PRs or commit history.
