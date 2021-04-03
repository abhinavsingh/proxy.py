[![Proxy.Py](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/ProxyPy.png)](https://github.com/abhinavsingh/proxy.py)

[![License](https://img.shields.io/github/license/abhinavsingh/proxy.py.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![PyPi Monthly](https://img.shields.io/pypi/dm/proxy.py.svg?color=green)](https://pypi.org/project/proxy.py/)
[![Docker Pulls](https://img.shields.io/docker/pulls/abhinavsingh/proxy.py?color=green)](https://hub.docker.com/r/abhinavsingh/proxy.py)
[![No Dependencies](https://img.shields.io/static/v1?label=dependencies&message=none&color=green)](https://github.com/abhinavsingh/proxy.py)

[![Proxy.py Library Build Status](https://github.com/abhinavsingh/proxy.py/workflows/Proxy.py%20Library/badge.svg)](https://github.com/abhinavsingh/proxy.py/actions)
[![Proxy.py Docker Build Status](https://github.com/abhinavsingh/proxy.py/workflows/Proxy.py%20Docker/badge.svg)](https://github.com/abhinavsingh/proxy.py/actions)
[![Proxy.py Docker Build Status](https://github.com/abhinavsingh/proxy.py/workflows/Proxy.py%20Dashboard/badge.svg)](https://github.com/abhinavsingh/proxy.py/actions)
[![Proxy.py Docker Build Status](https://github.com/abhinavsingh/proxy.py/workflows/Proxy.py%20Brew/badge.svg)](https://github.com/abhinavsingh/proxy.py/actions)
[![Coverage](https://codecov.io/gh/abhinavsingh/proxy.py/branch/develop/graph/badge.svg)](https://codecov.io/gh/abhinavsingh/proxy.py)

[![Tested With MacOS, Ubuntu, Windows, Android, Android Emulator, iOS, iOS Simulator](https://img.shields.io/static/v1?label=tested%20with&message=mac%20OS%20%F0%9F%92%BB%20%7C%20Ubuntu%20%F0%9F%96%A5%20%7C%20Windows%20%F0%9F%92%BB&color=brightgreen)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)
[![Android, Android Emulator](https://img.shields.io/static/v1?label=tested%20with&message=Android%20%F0%9F%93%B1%20%7C%20Android%20Emulator%20%F0%9F%93%B1&color=brightgreen)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)
[![iOS, iOS Simulator](https://img.shields.io/static/v1?label=tested%20with&message=iOS%20%F0%9F%93%B1%20%7C%20iOS%20Simulator%20%F0%9F%93%B1&color=brightgreen)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)

[![Maintenance](https://img.shields.io/static/v1?label=maintained%3F&message=yes&color=green)](https://gitHub.com/abhinavsingh/proxy.py/graphs/commit-activity)
[![Ask Me Anything](https://img.shields.io/static/v1?label=need%20help%3F&message=ask&color=green)](https://twitter.com/imoracle)
[![Contributions Welcome](https://img.shields.io/static/v1?label=contributions&message=welcome%20%F0%9F%91%8D&color=green)](https://github.com/abhinavsingh/proxy.py/issues)
[![Gitter](https://badges.gitter.im/proxy-py/community.svg)](https://gitter.im/proxy-py/community)

[![Python 3.x](https://img.shields.io/static/v1?label=Python&message=3.6%20%7C%203.7%20%7C%203.8%20%7C%203.9&color=blue)](https://www.python.org/)
[![Checked with mypy](https://img.shields.io/static/v1?label=MyPy&message=checked&color=blue)](http://mypy-lang.org/)

[![Become a Backer](https://opencollective.com/proxypy/tiers/backer.svg?avatarHeight=72)](https://opencollective.com/proxypy)

# Table of Contents

- [Features](#features)
- [Install](#install)
  - [Using PIP](#using-pip)
    - [Stable version](#stable-version-with-pip)
    - [Development version](#development-version-with-pip)
  - [Using Docker](#using-docker)
    - [Stable version](#stable-version-from-docker-hub)
    - [Development version](#build-development-version-locally)
  - [Using HomeBrew](#using-homebrew)
    - [Stable version](#stable-version-with-homebrew)
    - [Development version](#development-version-with-homebrew)
- [Start proxy.py](#start-proxypy)
  - [From command line when installed using PIP](#from-command-line-when-installed-using-pip)
    - [Run it](#run-it)
    - [Understanding logs](#understanding-logs)
    - [Enable DEBUG logging](#enable-debug-logging)
  - [From command line using repo source](#from-command-line-using-repo-source)
  - [Docker Image](#docker-image)
    - [Customize Startup Flags](#customize-startup-flags)
- [Plugin Examples](#plugin-examples)
  - [HTTP Proxy Plugins](#http-proxy-plugins)
    - [ShortLink Plugin](#shortlinkplugin)
    - [Modify Post Data Plugin](#modifypostdataplugin)
    - [Mock Api Plugin](#mockrestapiplugin)
    - [Redirect To Custom Server Plugin](#redirecttocustomserverplugin)
    - [Filter By Upstream Host Plugin](#filterbyupstreamhostplugin)
    - [Cache Responses Plugin](#cacheresponsesplugin)
    - [Man-In-The-Middle Plugin](#maninthemiddleplugin)
    - [Proxy Pool Plugin](#proxypoolplugin)
    - [FilterByClientIpPlugin](#filterbyclientipplugin)
    - [ModifyChunkResponsePlugin](#modifychunkresponseplugin)
  - [HTTP Web Server Plugins](#http-web-server-plugins)
    - [Reverse Proxy](#reverse-proxy)
    - [Web Server Route](#web-server-route)
  - [Plugin Ordering](#plugin-ordering)
- [End-to-End Encryption](#end-to-end-encryption)
- [TLS Interception](#tls-interception)
  - [TLS Interception With Docker](#tls-interception-with-docker)
- [Proxy Over SSH Tunnel](#proxy-over-ssh-tunnel)
  - [Proxy Remote Requests Locally](#proxy-remote-requests-locally)
  - [Proxy Local Requests Remotely](#proxy-local-requests-remotely)
- [Embed proxy.py](#embed-proxypy)
  - [Blocking Mode](#blocking-mode)
  - [Non-blocking Mode](#non-blocking-mode)
  - [Loading Plugins](#loading-plugins)
- [Unit testing with proxy.py](#unit-testing-with-proxypy)
  - [proxy.TestCase](#proxytestcase)
  - [Override Startup Flags](#override-startup-flags)
  - [With unittest.TestCase](#with-unittesttestcase)
- [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
  - [Everything is a plugin](#everything-is-a-plugin)
  - [Internal Architecture](#internal-architecture)
  - [Internal Documentation](#internal-documentation)
  - [Development Guide](#development-guide)
    - [Setup Local Environment](#setup-local-environment)
    - [Setup pre-commit hook](#setup-pre-commit-hook)
    - [Sending a Pull Request](#sending-a-pull-request)
- [Utilities](#utilities)
  - [TCP](#tcp-sockets)
    - [new_socket_connection](#new_socket_connection)
    - [socket_connection](#socket_connection)
  - [Http](#http-client)
    - [build_http_request](#build_http_request)
    - [build_http_response](#build_http_response)
  - [Public Key Infrastructure](#pki)
    - [API Usage](#api-usage)
    - [CLI Usage](#cli-usage)
- [Frequently Asked Questions](#frequently-asked-questions)
  - [Threads vs Threadless](#threads-vs-threadless)
  - [SyntaxError: invalid syntax](#syntaxerror-invalid-syntax)
  - [Unable to load plugins](#unable-to-load-plugins)
  - [Unable to connect with proxy.py from remote host](#unable-to-connect-with-proxypy-from-remote-host)
  - [Basic auth not working with a browser](#basic-auth-not-working-with-a-browser)
  - [Docker image not working on MacOS](#docker-image-not-working-on-macos)
  - [ValueError: filedescriptor out of range in select](#valueerror-filedescriptor-out-of-range-in-select)
  - [None:None in access logs](#nonenone-in-access-logs)
- [Flags](#flags)
- [Changelog](#changelog)
  - [v2.x](#v2x)
  - [v1.x](#v1x)
  - [v0.x](#v0x)

# Features
- Fast & Scalable

  - Scales by using all available cores on the system
  - Threadless executions using coroutine
  - Made to handle `tens-of-thousands` connections / sec

    ```bash
    # On Macbook Pro 2015 / 2.8 GHz Intel Core i7
    ❯ hey -n 10000 -c 100 http://localhost:8899/

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
  - Customize proxy and http routing via [plugins](https://github.com/abhinavsingh/proxy.py/tree/develop/proxy/plugin)
  - Enable plugin using command line option e.g. `--plugins proxy.plugin.CacheResponsesPlugin`
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
  - See [TLS Interception](#tls-interception)
- Supported proxy protocols
  - `http(s)`
    - `http1`
    - `http1.1` pipeline
  - `http2`
  - `websockets`
- Optimized for large file uploads and downloads
- IPv4 and IPv6 support
- Basic authentication support
- Can serve a [PAC (Proxy Auto-configuration)](https://en.wikipedia.org/wiki/Proxy_auto-config) file
  - See `--pac-file` and `--pac-file-url-path` flags

# Install

## Using PIP

### Stable Version with PIP

Install from `PyPi`

```bash
❯ pip install --upgrade proxy.py
```

or from GitHub `master` branch

```bash
❯ pip install git+https://github.com/abhinavsingh/proxy.py.git@master
```

### Development Version with PIP

```bash
❯ pip install git+https://github.com/abhinavsingh/proxy.py.git@develop
```

## Using Docker

#### Stable Version from Docker Hub

```bash
❯ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest
```

#### Build Development Version Locally

```bash
❯ git clone https://github.com/abhinavsingh/proxy.py.git
❯ cd proxy.py
❯ make container
❯ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest
```

[![WARNING](https://img.shields.io/static/v1?label=MacOS&message=warning&color=red)](https://github.com/moby/vpnkit/issues/469)
`docker` image is currently broken on `macOS` due to incompatibility with [vpnkit](https://github.com/moby/vpnkit/issues/469).

## Using HomeBrew

### Stable Version with HomeBrew

```bash
❯ brew install https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/helper/homebrew/stable/proxy.rb
```

### Development Version with HomeBrew

```bash
❯ brew install https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/helper/homebrew/develop/proxy.rb
```

# Start proxy.py

## From command line when installed using PIP

When `proxy.py` is installed using `pip`,
an executable named `proxy` is placed under your `$PATH`.

#### Run it

Simply type `proxy` on command line to start it with default configuration.

```bash
❯ proxy
...[redacted]... - Loaded plugin proxy.http_proxy.HttpProxyPlugin
...[redacted]... - Starting 8 workers
...[redacted]... - Started server on ::1:8899
```

#### Understanding logs

Things to notice from above logs:

- `Loaded plugin` - `proxy.py` will load `proxy.http.proxy.HttpProxyPlugin` by default.
  As name suggests, this core plugin adds `http(s)` proxy server capabilities to `proxy.py`

- `Started N workers` - Use `--num-workers` flag to customize number of worker processes.
  By default, `proxy.py` will start as many workers as there are CPU cores on the machine.

- `Started server on ::1:8899` - By default, `proxy.py` listens on IPv6 `::1`, which
  is equivalent of IPv4 `127.0.0.1`. If you want to access `proxy.py` externally,
  use `--hostname ::` or `--hostname 0.0.0.0` or bind to any other interface available
  on your machine.

- `Port 8899` - Use `--port` flag to customize default TCP port.

#### Enable DEBUG logging

All the logs above are `INFO` level logs, default `--log-level` for `proxy.py`.

Lets start `proxy.py` with `DEBUG` level logging:

```bash
❯ proxy --log-level d
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

  ```bash
  ❯ git clone https://github.com/abhinavsingh/proxy.py.git
  ❯ cd proxy.py
  ```

- Create a Python 3 virtual env

  ```bash
  ❯ python3 -m venv venv
  ❯ source venv/bin/activate
  ```

- Install deps

  ```bash
  ❯ pip install -r requirements.txt
  ❯ pip install -r requirements-testing.txt
  ```

- Run tests

  ```bash
  ❯ make
  ```

- Run proxy.py

  ```bash
  ❯ python -m proxy
  ```

Also see [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
if you plan to work with `proxy.py` source code.

## Docker image

#### Customize startup flags

By default `docker` binary is started with IPv4 networking flags:

    --hostname 0.0.0.0 --port 8899

To override input flags, start docker image as follows.
For example, to check `proxy.py` version within Docker image:

    ❯ docker run -it \
        -p 8899:8899 \
        --rm abhinavsingh/proxy.py:latest \
        -v

# Plugin Examples

- See [plugin](https://github.com/abhinavsingh/proxy.py/tree/develop/proxy/plugin) module for full code.
- All the bundled plugin examples also works with `https` traffic
  - Require additional flags and certificate generation
  - See [TLS Interception](#tls-interception).
- Plugin examples are also bundled with Docker image.
  - See [Customize startup flags](#customize-startup-flags) to try plugins with Docker image.

## HTTP Proxy Plugins

### ShortLinkPlugin

Add support for short links in your favorite browsers / applications.

[![Shortlink Plugin](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/shortlink.gif)](https://github.com/abhinavsingh/proxy.py#shortlinkplugin)

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.ShortLinkPlugin
```

Now you can speed up your daily browsing experience by visiting your
favorite website using single character domain names :). This works
across all browsers.

Following short links are enabled by default:

| Short Link | Destination URL  |
| :--------: | :--------------: |
|     a/     |    amazon.com    |
|     i/     |  instagram.com   |
|     l/     |   linkedin.com   |
|     f/     |   facebook.com   |
|     g/     |    google.com    |
|     t/     |   twitter.com    |
|     w/     | web.whatsapp.com |
|     y/     |   youtube.com    |
|   proxy/   |  localhost:8899  |

### ModifyPostDataPlugin

Modifies POST request body before sending request to upstream server.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.ModifyPostDataPlugin
```

By default plugin replaces POST body content with hardcoded `b'{"key": "modified"}'`
and enforced `Content-Type: application/json`.

Verify the same using `curl -x localhost:8899 -d '{"key": "value"}' http://httpbin.org/post`

```bash
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

### MockRestApiPlugin

Mock responses for your server REST API.
Use to test and develop client side applications
without need of an actual upstream REST API server.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.ProposedRestApiPlugin
```

Verify mock API response using `curl -x localhost:8899 http://api.example.com/v1/users/`

```bash
{"count": 2, "next": null, "previous": null, "results": [{"email": "you@example.com", "groups": [], "url": "api.example.com/v1/users/1/", "username": "admin"}, {"email": "someone@example.com", "groups": [], "url": "api.example.com/v1/users/2/", "username": "admin"}]}
```

Verify the same by inspecting `proxy.py` logs:

```bash
2019-09-27 12:44:02,212 - INFO - pid:7077 - access_log:1210 - ::1:64792 - GET None:None/v1/users/ - None None - 0 byte
```

Access log shows `None:None` as server `ip:port`. `None` simply means that
the server connection was never made, since response was returned by our plugin.

Now modify `ProposedRestApiPlugin` to returns REST API mock
responses as expected by your clients.

### RedirectToCustomServerPlugin

Redirects all incoming `http` requests to custom web server.
By default, it redirects client requests to inbuilt web server,
also running on `8899` port.

Start `proxy.py` and enable inbuilt web server:

```bash
❯ proxy \
    --enable-web-server \
    --plugins proxy.plugin.RedirectToCustomServerPlugin
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

### FilterByUpstreamHostPlugin

Drops traffic by inspecting upstream host.
By default, plugin drops traffic for `google.com` and `www.google.com`.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.FilterByUpstreamHostPlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`:

```bash
... [redacted] ...
< HTTP/1.1 418 I'm a tea pot
< Proxy-agent: proxy.py v1.0.0
* no chunk, no close, no size. Assume close to signal end
<
* Closing connection 0
```

Above `418 I'm a tea pot` is sent by our plugin.

Verify the same by inspecting logs for `proxy.py`:

```bash
2019-09-24 19:21:37,893 - ERROR - pid:50074 - handle_readables:1347 - HttpProtocolException type raised
Traceback (most recent call last):
... [redacted] ...
2019-09-24 19:21:37,897 - INFO - pid:50074 - access_log:1157 - ::1:49911 - GET None:None/ - None None - 0 bytes
```

### CacheResponsesPlugin

Caches Upstream Server Responses.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.CacheResponsesPlugin
```

Verify using `curl -v -x localhost:8899 http://httpbin.org/get`:

```bash
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

```bash
... [redacted] ... - GET httpbin.org:80/get - 200 OK - 556 bytes
... [redacted] ... - Cached response at /var/folders/k9/x93q0_xn1ls9zy76m2mf2k_00000gn/T/httpbin.org-1569378301.407512.txt
```

Verify contents of the cache file `cat /path/to/your/cache/httpbin.org.txt`

```bash
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

### ManInTheMiddlePlugin

Modifies upstream server responses.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.ManInTheMiddlePlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`:

```bash
... [redacted] ...
< HTTP/1.1 200 OK
< Content-Length: 28
<
* Connection #0 to host localhost left intact
Hello from man in the middle
```

Response body `Hello from man in the middle` is sent by our plugin.

### ProxyPoolPlugin

Forward incoming proxy requests to a set of upstream proxy servers.

By default, `ProxyPoolPlugin` is hard-coded to use
`localhost:9000` and `localhost:9001` as upstream proxy server.

Let's start upstream proxies first.

Start `proxy.py` on port `9000` and `9001`

```bash
❯ proxy --port 9000
```

```bash
❯ proxy --port 9001
```

Now, start `proxy.py` with `ProxyPoolPlugin` (on default `8899` port):

```bash
❯ proxy \
    --plugins proxy.plugin.ProxyPoolPlugin
```

Make a curl request via `8899` proxy:

`curl -v -x localhost:8899 http://httpbin.org/get`

Verify that `8899` proxy forwards requests to upstream proxies
by checking respective logs.

### FilterByClientIpPlugin

Reject traffic from specific IP addresses. By default this
plugin blocks traffic from `127.0.0.1` and `::1`.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.FilterByClientIpPlugin
```

Send a request using `curl -v -x localhost:8899 http://google.com`:

```bash
... [redacted] ...
> Proxy-Connection: Keep-Alive
>
< HTTP/1.1 418 I'm a tea pot
< Connection: close
<
* Closing connection 0
```

Modify plugin to your taste e.g. Allow specific IP addresses only.

### ModifyChunkResponsePlugin

This plugin demonstrate how to modify chunked encoded responses. In able to do so, this plugin uses `proxy.py` core to parse the chunked encoded response. Then we reconstruct the response using custom hardcoded chunks, ignoring original chunks received from upstream server.

Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.ModifyChunkResponsePlugin
```

Verify using `curl -v -x localhost:8899 http://httpbin.org/stream/5`:

```bash
... [redacted] ...
modify
chunk
response
plugin
* Connection #0 to host localhost left intact
* Closing connection 0
```

Modify `ModifyChunkResponsePlugin` to your taste. Example, instead of sending hardcoded chunks, parse and modify the original `JSON` chunks received from the upstream server.

## HTTP Web Server Plugins

### Reverse Proxy

Extend in-built Web Server to add Reverse Proxy capabilities.

Start `proxy.py` as:

```bash
❯ proxy --enable-web-server \
    --plugins proxy.plugin.ReverseProxyPlugin
```

With default configuration, `ReverseProxyPlugin` plugin is equivalent to
following `Nginx` config:

```bash
location /get {
    proxy_pass http://httpbin.org/get
}
```

Verify using `curl -v localhost:8899/get`:

```bash
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "localhost",
    "User-Agent": "curl/7.64.1"
  },
  "origin": "1.2.3.4, 5.6.7.8",
  "url": "https://localhost/get"
}
```

### Web Server Route

Demonstrates inbuilt web server routing using plugin.

Start `proxy.py` as:

```bash
❯ proxy --enable-web-server \
    --plugins proxy.plugin.WebServerPlugin
```

Verify using `curl -v localhost:8899/http-route-example`, should return:

```bash
HTTP route response
```

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

# End-to-End Encryption

By default, `proxy.py` uses `http` protocol for communication with clients e.g. `curl`, `browser`.
For enabling end-to-end encrypting using `tls` / `https` first generate certificates:

```bash
make https-certificates
```

Start `proxy.py` as:

```bash
❯ proxy \
    --cert-file https-cert.pem \
    --key-file https-key.pem
```

Verify using `curl -x https://localhost:8899 --proxy-cacert https-cert.pem https://httpbin.org/get`:

```bash
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

If you want to avoid passing `--proxy-cacert` flag, also consider signing generated SSL certificates. Example:

First, generate CA certificates:

```bash
make ca-certificates
```

Then, sign SSL certificate:

```bash
make sign-https-certificates
```

Now restart the server with `--cert-file https-signed-cert.pem` flag. Note that you must also trust generated `ca-cert.pem` in your system keychain.

# TLS Interception

By default, `proxy.py` will not decrypt `https` traffic between client and server.
To enable TLS interception first generate root CA certificates:

```bash
❯ make ca-certificates
```

Lets also enable `CacheResponsePlugin` so that we can verify decrypted
response from the server. Start `proxy.py` as:

```bash
❯ proxy \
    --plugins proxy.plugin.CacheResponsesPlugin \
    --ca-key-file ca-key.pem \
    --ca-cert-file ca-cert.pem \
    --ca-signing-key-file ca-signing-key.pem
```

[![NOTE](https://img.shields.io/static/v1?label=MacOS&message=note&color=yellow)](https://github.com/abhinavsingh/proxy.py#flags) Also provide explicit CA bundle path needed for validation of peer certificates. See `--ca-file` flag.

Verify TLS interception using `curl`

```bash
❯ curl -v -x localhost:8899 --cacert ca-cert.pem https://httpbin.org/get
```

```bash
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

Also verify the contents of cached response file. Get path to the cache
file from `proxy.py` logs.

`❯ cat /path/to/your/tmp/directory/httpbin.org-1569452863.924174.txt`

```bash
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

Viola!!! If you remove CA flags, encrypted data will be found in the
cached file instead of plain text.

Now use CA flags with other
[plugin examples](#plugin-examples) to see them work with `https` traffic.

## TLS Interception With Docker

Important notes about TLS Interception with Docker container:

- Since `v2.2.0`, `proxy.py` docker container also ships with `openssl`. This allows `proxy.py`
  to generate certificates on the fly for TLS Interception.

- For security reasons, `proxy.py` docker container doesn't ship with CA certificates.

Here is how to start a `proxy.py` docker container
with TLS Interception:

1. Generate CA certificates on host computer

   ```bash
   ❯ make ca-certificates
   ```

2. Copy all generated certificates into a separate directory. We'll later mount this directory into our docker container

   ```bash
   ❯ mkdir /tmp/ca-certificates
   ❯ cp ca-cert.pem ca-key.pem ca-signing-key.pem /tmp/ca-certificates
   ```

3. Start docker container

   ```bash
   ❯ docker run -it --rm \
       -v /tmp/ca-certificates:/tmp/ca-certificates \
       -p 8899:8899 \
       abhinavsingh/proxy.py:latest \
       --hostname 0.0.0.0 \
       --plugins proxy.plugin.CacheResponsesPlugin \
       --ca-key-file /tmp/ca-certificates/ca-key.pem \
       --ca-cert-file /tmp/ca-certificates/ca-cert.pem \
       --ca-signing-key /tmp/ca-certificates/ca-signing-key.pem
   ```

   - `-v /tmp/ca-certificates:/tmp/ca-certificates` flag mounts our CA certificate directory in container environment
   - `--plugins proxy.plugin.CacheResponsesPlugin` enables `CacheResponsesPlugin` so that we can inspect intercepted traffic
   - `--ca-*` flags enable TLS Interception.

4. From another terminal, try TLS Interception using `curl`. You can omit `--cacert` flag if CA certificate is already trusted by the system.

   ```bash
   ❯ curl -v \
       --cacert ca-cert.pem \
       -x 127.0.0.1:8899 \
       https://httpbin.org/get
   ```

5. Verify `issuer` field from response headers.

   ```bash
   * Server certificate:
   *  subject: CN=httpbin.org; C=NA; ST=Unavailable; L=Unavailable; O=Unavailable; OU=Unavailable
   *  start date: Jun 17 09:26:57 2020 GMT
   *  expire date: Jun 17 09:26:57 2022 GMT
   *  subjectAltName: host "httpbin.org" matched cert's "httpbin.org"
   *  issuer: CN=example.com
   *  SSL certificate verify ok.
   ```

6. Back on docker terminal, copy response dump path logs.

   ```bash
   ...[redacted]... [I] access_log:338 - 172.17.0.1:56498 - CONNECT httpbin.org:443 - 1031 bytes - 1216.70 ms
   ...[redacted]... [I] close:49 - Cached response at /tmp/httpbin.org-ae1a927d064e4ab386ea319eb38fe251.txt
   ```

7. In another terminal, `cat` the response dump:

   ```bash
   ❯ docker exec -it $(docker ps | grep proxy.py | awk '{ print $1 }') cat /tmp/httpbin.org-ae1a927d064e4ab386ea319eb38fe251.txt
   HTTP/1.1 200 OK
   ...[redacted]...
   {
     ...[redacted]...,
     "url": "http://httpbin.org/get"
   }
   ```

# Proxy Over SSH Tunnel

**This is a WIP and may not work as documented**

Requires `paramiko` to work. See [requirements-tunnel.txt](https://github.com/abhinavsingh/proxy.py/blob/develop/requirements-tunnel.txt)

## Proxy Remote Requests Locally

                            |
    +------------+          |            +----------+
    |   LOCAL    |          |            |  REMOTE  |
    |   HOST     | <== SSH ==== :8900 == |  SERVER  |
    +------------+          |            +----------+
    :8899 proxy.py          |
                            |
                         FIREWALL
                      (allow tcp/22)

## What

Proxy HTTP(s) requests made on a `remote` server through `proxy.py` server
running on `localhost`.

### How

- Requested `remote` port is forwarded over the SSH connection.
- `proxy.py` running on the `localhost` handles and responds to
  `remote` proxy requests.

### Requirements

1. `localhost` MUST have SSH access to the `remote` server
2. `remote` server MUST be configured to proxy HTTP(s) requests
   through the forwarded port number e.g. `:8900`.
   - `remote` and `localhost` ports CAN be same e.g. `:8899`.
   - `:8900` is chosen in ascii art for differentiation purposes.

### Try it

Start `proxy.py` as:

```bash
❯ # On localhost
❯ proxy --enable-tunnel \
    --tunnel-username username \
    --tunnel-hostname ip.address.or.domain.name \
    --tunnel-port 22 \
    --tunnel-remote-host 127.0.0.1
    --tunnel-remote-port 8899
```

Make a HTTP proxy request on `remote` server and
verify that response contains public IP address of `localhost` as origin:

```bash
❯ # On remote
❯ curl -x 127.0.0.1:8899 http://httpbin.org/get
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/7.54.0"
  },
  "origin": "x.x.x.x, y.y.y.y",
  "url": "https://httpbin.org/get"
}
```

Also, verify that `proxy.py` logs on `localhost` contains `remote` IP as client IP.

```bash
access_log:328 - remote:52067 - GET httpbin.org:80
```

## Proxy Local Requests Remotely

                            |
    +------------+          |     +----------+
    |   LOCAL    |          |     |  REMOTE  |
    |   HOST     | === SSH =====> |  SERVER  |
    +------------+          |     +----------+
                            |     :8899 proxy.py
                            |
                        FIREWALL
                     (allow tcp/22)

# Embed proxy.py

## Blocking Mode

Start `proxy.py` in embedded mode with default configuration
by using `proxy.main` method. Example:

```python
import proxy

if __name__ == '__main__':
  proxy.main()
```

Customize startup flags by passing list of input arguments:

```python
import proxy

if __name__ == '__main__':
  proxy.main([
    '--hostname', '::1',
    '--port', '8899'
  ])
```

or, customize startup flags by passing them as kwargs:

```python
import ipaddress
import proxy

if __name__ == '__main__':
  proxy.main(
    hostname=ipaddress.IPv6Address('::1'),
    port=8899
  )
```

Note that:

1. Calling `main` is simply equivalent to starting `proxy.py` from command line.
2. `main` will block until `proxy.py` shuts down.

## Non-blocking Mode

Start `proxy.py` in non-blocking embedded mode with default configuration
by using `start` method: Example:

```python
import proxy

if __name__ == '__main__':
  with proxy.start([]):
    # ... your logic here ...
```

Note that:

1. `start` is similar to `main`, except `start` won't block.
1. `start` is a context manager.
   It will start `proxy.py` when called and will shut it down
   once scope ends.
1. Just like `main`, startup flags with `start` method
   can be customized by either passing flags as list of
   input arguments e.g. `start(['--port', '8899'])` or
   by using passing flags as kwargs e.g. `start(port=8899)`.

## Loading Plugins

You can, of course, list plugins to load in the input arguments list of `proxy.main`, `proxy.start` or the `Proxy` constructor. Use the `--plugins` flag as when starting from command line:

```python
import proxy

if __name__ == '__main__':
  proxy.main([
    '--plugins', 'proxy.plugin.CacheResponsesPlugin',
  ])
```

However, for simplicity you can pass the list of plugins to load as a keyword argument to `proxy.main`, `proxy.start` or the `Proxy` constructor:

```python
import proxy
from proxy.plugin import FilterByUpstreamHostPlugin

if __name__ == '__main__':
  proxy.main([], plugins=[
    b'proxy.plugin.CacheResponsesPlugin',
    FilterByUpstreamHostPlugin,
  ])
```

Note that it supports:

1. The fully-qualified name of a class as `bytes`
2. Any `type` instance for a Proxy.py plugin class. This is espacially useful for custom plugins defined locally.

# Unit testing with proxy.py

## proxy.TestCase

To setup and teardown `proxy.py` for your Python unittest classes,
simply use `proxy.TestCase` instead of `unittest.TestCase`.
Example:

```python
import proxy


class TestProxyPyEmbedded(proxy.TestCase):

    def test_my_application_with_proxy(self) -> None:
        self.assertTrue(True)
```

Note that:

1. `proxy.TestCase` overrides `unittest.TestCase.run()` method to setup and teardown `proxy.py`.
2. `proxy.py` server will listen on a random available port on the system.
   This random port is available as `self.PROXY_PORT` within your test cases.
3. Only a single worker is started by default (`--num-workers 1`) for faster setup and teardown.
4. Most importantly, `proxy.TestCase` also ensures `proxy.py` server
   is up and running before proceeding with execution of tests. By default,
   `proxy.TestCase` will wait for `10 seconds` for `proxy.py` server to start,
   upon failure a `TimeoutError` exception will be raised.

## Override startup flags

To override default startup flags, define a `PROXY_PY_STARTUP_FLAGS` variable in your test class.
Example:

```python
class TestProxyPyEmbedded(TestCase):

    PROXY_PY_STARTUP_FLAGS = [
        '--num-workers', '1',
        '--enable-web-server',
    ]

    def test_my_application_with_proxy(self) -> None:
        self.assertTrue(True)
```

See [test_embed.py](https://github.com/abhinavsingh/proxy.py/blob/develop/tests/test_embed.py)
for full working example.

## With unittest.TestCase

If for some reasons you are unable to directly use `proxy.TestCase`,
then simply override `unittest.TestCase.run` yourself to setup and teardown `proxy.py`.
Example:

```python
import unittest
import proxy


class TestProxyPyEmbedded(unittest.TestCase):

    def test_my_application_with_proxy(self) -> None:
        self.assertTrue(True)

    def run(self, result: Optional[unittest.TestResult] = None) -> Any:
        with proxy.start([
                '--num-workers', '1',
                '--port', '... random port ...']):
            super().run(result)
```

or simply setup / teardown `proxy.py` within
`setUpClass` and `teardownClass` class methods.

# Plugin Developer and Contributor Guide

## Everything is a plugin

As you might have guessed by now, in `proxy.py` everything is a plugin.

- We enabled proxy server plugins using `--plugins` flag.
  All the [plugin examples](#plugin-examples) were implementing
  `HttpProxyBasePlugin`. See documentation of
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

## Development Guide

### Setup Local Environment

Contributors must start `proxy.py` from source to verify and develop new features / fixes.

See [Run proxy.py from command line using repo source](#from-command-line-using-repo-source) for details.

### Setup pre-commit hook

Pre-commit hook ensures lint checking and tests execution.

1. `cd /path/to/proxy.py`
2. `ln -s $(PWD)/git-pre-commit .git/hooks/pre-commit`

### Sending a Pull Request

Every pull request is tested using GitHub actions.

See [GitHub workflow](https://github.com/abhinavsingh/proxy.py/tree/develop/.github/workflows)
for list of tests.

# Utilities

## TCP Sockets

### new_socket_connection

Attempts to create an IPv4 connection, then IPv6 and
finally a dual stack connection to provided address.

```python
>>> conn = new_socket_connection(('httpbin.org', 80))
>>> ...[ use connection ]...
>>> conn.close()
```

### socket_connection

`socket_connection` is a convenient decorator + context manager
around `new_socket_connection` which ensures `conn.close` is implicit.

As a context manager:

```python
>>> with socket_connection(('httpbin.org', 80)) as conn:
>>>   ... [ use connection ] ...
```

As a decorator:

```python
>>> @socket_connection(('httpbin.org', 80))
>>> def my_api_call(conn, *args, **kwargs):
>>>   ... [ use connection ] ...
```

## Http Client

### build_http_request

#### Generate HTTP GET request

```python
>>> build_http_request(b'GET', b'/')
b'GET / HTTP/1.1\r\n\r\n'
>>>
```

#### Generate HTTP GET request with headers

```python
>>> build_http_request(b'GET', b'/',
        headers={b'Connection': b'close'})
b'GET / HTTP/1.1\r\nConnection: close\r\n\r\n'
>>>
```

#### Generate HTTP POST request with headers and body

```python
>>> import json
>>> build_http_request(b'POST', b'/form',
        headers={b'Content-type': b'application/json'},
        body=proxy.bytes_(json.dumps({'email': 'hello@world.com'})))
    b'POST /form HTTP/1.1\r\nContent-type: application/json\r\n\r\n{"email": "hello@world.com"}'
```

### build_http_response

```python
build_http_response(
    status_code: int,
    protocol_version: bytes = HTTP_1_1,
    reason: Optional[bytes] = None,
    headers: Optional[Dict[bytes, bytes]] = None,
    body: Optional[bytes] = None) -> bytes
```

## PKI

### API Usage

#### gen_private_key

```python
gen_private_key(
    key_path: str,
    password: str,
    bits: int = 2048,
    timeout: int = 10) -> bool
```

#### gen_public_key

```python
gen_public_key(
    public_key_path: str,
    private_key_path: str,
    private_key_password: str,
    subject: str,
    alt_subj_names: Optional[List[str]] = None,
    extended_key_usage: Optional[str] = None,
    validity_in_days: int = 365,
    timeout: int = 10) -> bool
```

#### remove_passphrase

```python
remove_passphrase(
    key_in_path: str,
    password: str,
    key_out_path: str,
    timeout: int = 10) -> bool
```

#### gen_csr

```python
gen_csr(
    csr_path: str,
    key_path: str,
    password: str,
    crt_path: str,
    timeout: int = 10) -> bool
```

#### sign_csr

```python
sign_csr(
    csr_path: str,
    crt_path: str,
    ca_key_path: str,
    ca_key_password: str,
    ca_crt_path: str,
    serial: str,
    alt_subj_names: Optional[List[str]] = None,
    extended_key_usage: Optional[str] = None,
    validity_in_days: int = 365,
    timeout: int = 10) -> bool
```

See [pki.py](https://github.com/abhinavsingh/proxy.py/blob/develop/proxy/common/pki.py) and
[test_pki.py](https://github.com/abhinavsingh/proxy.py/blob/develop/tests/common/test_pki.py)
for usage examples.

### CLI Usage

Use `proxy.common.pki` module for:

1. Generation of public and private keys
2. Generating CSR requests
3. Signing CSR requests using custom CA.

```bash
python -m proxy.common.pki -h
usage: pki.py [-h] [--password PASSWORD] [--private-key-path PRIVATE_KEY_PATH]
              [--public-key-path PUBLIC_KEY_PATH] [--subject SUBJECT]
              action

proxy.py v2.2.0 : PKI Utility

positional arguments:
  action                Valid actions: remove_passphrase, gen_private_key,
                        gen_public_key, gen_csr, sign_csr

optional arguments:
  -h, --help            show this help message and exit
  --password PASSWORD   Password to use for encryption. Default: proxy.py
  --private-key-path PRIVATE_KEY_PATH
                        Private key path
  --public-key-path PUBLIC_KEY_PATH
                        Public key path
  --subject SUBJECT     Subject to use for public key generation. Default:
                        /CN=example.com
```

## Internal Documentation

Browse through internal class hierarchy and documentation using `pydoc3`.
Example:

```bash
❯ pydoc3 proxy

PACKAGE CONTENTS
    __main__
    common (package)
    core (package)
    http (package)
    main

FILE
    /Users/abhinav/Dev/proxy.py/proxy/__init__.py
```

# Frequently Asked Questions

## Threads vs Threadless

Pre v2.x, `proxy.py` used to spawn new threads for handling
client requests.

Starting v2.x, `proxy.py` added support for threadless execution of
client requests using `asyncio`.

In future, threadless execution will be the default mode.

Till then if you are interested in trying it out,
start `proxy.py` with `--threadless` flag.

## SyntaxError: invalid syntax

`proxy.py` is strictly typed and uses Python `typing` annotations. Example:

```python
>>> my_strings : List[str] = []
>>> #############^^^^^^^^^#####
```

Hence a Python version that understands typing annotations is required.
Make sure you are using `Python 3.6+`.

Verify the version before running `proxy.py`:

`❯ python --version`

All `typing` annotations can be replaced with `comment-only` annotations. Example:

```python
>>> my_strings = [] # List[str]
>>> ################^^^^^^^^^^^
```

It will enable `proxy.py` to run on Python `pre-3.6`, even on `2.7`.
However, as all future versions of Python will support `typing` annotations,
this has not been considered.

## Unable to load plugins

Make sure plugin modules are discoverable by adding them to `PYTHONPATH`. Example:

`PYTHONPATH=/path/to/my/app proxy --plugins my_app.proxyPlugin`

```bash
...[redacted]... - Loaded plugin proxy.HttpProxyPlugin
...[redacted]... - Loaded plugin my_app.proxyPlugin
```

OR, simply pass fully-qualified path as parameter, e.g.

`proxy --plugins /path/to/my/app/my_app.proxyPlugin`

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
2. Make sure to adjust `--backlog` flag for higher concurrency.

If nothing helps, [open an issue](https://github.com/abhinavsingh/proxy.py/issues/new)
with `requests per second` sent and output of following debug script:

```bash
❯ ./helper/monitor_open_files.sh <proxy-py-pid>
```

## None:None in access logs

Sometimes you may see `None:None` in access logs. It simply means
that an upstream server connection was never established i.e.
`upstream_host=None`, `upstream_port=None`.

There can be several reasons for no upstream connection,
few obvious ones include:

1. Client established a connection but never completed the request.
2. A plugin returned a response prematurely, avoiding connection to upstream server.

# Flags

```bash
❯ proxy -h
usage: proxy [-h] [--threadless] [--backlog BACKLOG] [--enable-events]
          [--hostname HOSTNAME] [--port PORT] [--num-workers NUM_WORKERS]
          [--client-recvbuf-size CLIENT_RECVBUF_SIZE] [--key-file KEY_FILE]
          [--timeout TIMEOUT] [--pid-file PID_FILE] [--version]
          [--disable-http-proxy] [--enable-dashboard] [--enable-devtools]
          [--enable-static-server] [--enable-web-server]
          [--log-level LOG_LEVEL] [--log-file LOG_FILE]
          [--log-format LOG_FORMAT] [--open-file-limit OPEN_FILE_LIMIT]
          [--plugins PLUGINS] [--ca-key-file CA_KEY_FILE]
          [--ca-cert-dir CA_CERT_DIR] [--ca-cert-file CA_CERT_FILE]
          [--ca-file CA_FILE] [--ca-signing-key-file CA_SIGNING_KEY_FILE]
          [--cert-file CERT_FILE] [--disable-headers DISABLE_HEADERS]
          [--server-recvbuf-size SERVER_RECVBUF_SIZE]
          [--basic-auth BASIC_AUTH] [--cache-dir CACHE_DIR]
          [--static-server-dir STATIC_SERVER_DIR] [--pac-file PAC_FILE]
          [--pac-file-url-path PAC_FILE_URL_PATH]
          [--filtered-client-ips FILTERED_CLIENT_IPS]

proxy.py v2.3.1

optional arguments:
  -h, --help            show this help message and exit
  --threadless          Default: False. When disabled a new thread is spawned
                        to handle each client connection.
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --enable-events       Default: False. Enables core to dispatch lifecycle
                        events. Plugins can be used to subscribe for core
                        events.
  --hostname HOSTNAME   Default: ::1. Server IP address.
  --port PORT           Default: 8899. Server port.
  --num-workers NUM_WORKERS
                        Defaults to number of CPU cores.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --key-file KEY_FILE   Default: None. Server key file to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --cert-file.
  --timeout TIMEOUT     Default: 10. Number of seconds after which an inactive
                        connection must be dropped. Inactivity is defined by
                        no data sent or received by the client.
  --pid-file PID_FILE   Default: None. Save parent process ID to a file.
  --version, -v         Prints proxy.py version.
  --disable-http-proxy  Default: False. Whether to disable
                        proxy.HttpProxyPlugin.
  --enable-dashboard    Default: False. Enables proxy.py dashboard.
  --enable-devtools     Default: False. Enables integration with Chrome
                        Devtool Frontend. Also see --devtools-ws-path.
  --enable-static-server
                        Default: False. Enable inbuilt static file server.
                        Optionally, also use --static-server-dir to serve
                        static content from custom directory. By default,
                        static file server serves out of installed proxy.py
                        python module folder.
  --enable-web-server   Default: False. Whether to enable
                        proxy.HttpWebServerPlugin.
  --log-level LOG_LEVEL
                        Valid options: DEBUG, INFO (default), WARNING, ERROR,
                        CRITICAL. Both upper and lowercase values are allowed.
                        You may also simply use the leading character e.g.
                        --log-level d
  --log-file LOG_FILE   Default: sys.stdout. Log file destination.
  --log-format LOG_FORMAT
                        Log format for Python logger.
  --open-file-limit OPEN_FILE_LIMIT
                        Default: 1024. Maximum number of files (TCP
                        connections) that proxy.py can open concurrently.
  --plugins PLUGINS     Comma separated plugins
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
  --ca-file CA_FILE     Default: None. Provide path to custom CA file for peer
                        certificate validation. Specially useful on MacOS.
  --ca-signing-key-file CA_SIGNING_KEY_FILE
                        Default: None. CA signing key to use for dynamic
                        generation of HTTPS certificates. If used, must also
                        pass --ca-key-file and --ca-cert-file
  --cert-file CERT_FILE
                        Default: None. Server certificate to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --key-file.
  --disable-headers DISABLE_HEADERS
                        Default: None. Comma separated list of headers to
                        remove before dispatching client request to upstream
                        server.
  --server-recvbuf-size SERVER_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the server in a single recv() operation. Bump this
                        value for faster downloads at the expense of increased
                        RAM.
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --cache-dir CACHE_DIR
                        Default: A temporary directory. Flag only applicable
                        when cache plugin is used with on-disk storage.
  --static-server-dir STATIC_SERVER_DIR
                        Default: "public" folder in directory where proxy.py
                        is placed. This option is only applicable when static
                        server is also enabled. See --enable-static-server.
  --pac-file PAC_FILE   A file (Proxy Auto Configuration) or string to serve
                        when the server receives a direct file request. Using
                        this option enables proxy.HttpWebServerPlugin.
  --pac-file-url-path PAC_FILE_URL_PATH
                        Default: /. Web server path to serve the PAC file.
  --filtered-client-ips FILTERED_CLIENT_IPS
                        Default: 127.0.0.1,::1. Comma separated list of IPv4
                        and IPv6 addresses.

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```

# Changelog

## v2.x

- No longer ~~a single file module~~.
- Added support for threadless execution.
- Added dashboard app.
- Added support for unit testing.

## v1.x

- `Python3` only.
  - Deprecated support for ~~Python 2.x~~.
- Added support multi core accept.
- Added plugin support.

## v0.x

- Single file.
- Single threaded server.

For detailed changelog refer to release PRs or commit history.
