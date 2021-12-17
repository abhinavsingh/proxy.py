[![Proxy.Py](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/ProxyPy.png)](https://github.com/abhinavsingh/proxy.py)

[//]: # (DO-NOT-REMOVE-docs-badges-START)

[![PyPi Monthly](https://img.shields.io/pypi/dm/proxy.py?style=for-the-badge&color=darkgreen)](https://pypi.org/project/proxy.py/)
[![Docker Pulls](https://img.shields.io/docker/pulls/abhinavsingh/proxy.py?style=for-the-badge&color=darkgreen)](https://hub.docker.com/r/abhinavsingh/proxy.py)
[![No Dependencies](https://img.shields.io/static/v1?label=dependencies&message=0&style=for-the-badge&color=darkgreen)](https://github.com/abhinavsingh/proxy.py)
[![Gitter](https://img.shields.io/gitter/room/abhinavsingh/proxy.py?style=for-the-badge&color=darkgreen)](https://gitter.im/proxy-py/community)
[![License](https://img.shields.io/github/license/abhinavsingh/proxy.py?style=for-the-badge&color=darkgreen)](https://github.com/abhinavsingh/proxy.py/blob/develop/LICENSE)

[![Tested With MacOS, Ubuntu, Windows, Android, Android Emulator, iOS, iOS Simulator](https://img.shields.io/static/v1?label=tested%20with&message=mac%20OS%20%F0%9F%92%BB%20%7C%20Ubuntu%20%F0%9F%96%A5%20%7C%20Windows%20%F0%9F%92%BB&color=darkgreen&style=for-the-badge)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)
[![Android, Android Emulator](https://img.shields.io/static/v1?label=tested%20with&message=Android%20%F0%9F%93%B1%20%7C%20Android%20Emulator%20%F0%9F%93%B1&color=darkgreen&style=for-the-badge)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)
[![iOS, iOS Simulator](https://img.shields.io/static/v1?label=tested%20with&message=iOS%20%F0%9F%93%B1%20%7C%20iOS%20Simulator%20%F0%9F%93%B1&color=darkgreen&style=for-the-badge)](https://abhinavsingh.com/proxy-py-a-lightweight-single-file-http-proxy-server-in-python/)

[![pypi version](https://img.shields.io/pypi/v/proxy.py)](https://pypi.org/project/proxy.py/)
[![Python 3.x](https://img.shields.io/static/v1?label=Python&message=3.6%20%7C%203.7%20%7C%203.8%20%7C%203.9%20%7C%203.10&color=blue)](https://www.python.org/)
[![Checked with mypy](https://img.shields.io/static/v1?label=MyPy&message=checked&color=blue)](http://mypy-lang.org/)
[![lib](https://github.com/abhinavsingh/proxy.py/actions/workflows/test-library.yml/badge.svg)](https://github.com/abhinavsingh/proxy.py/actions/workflows/test-library.yml)
[![codecov](https://codecov.io/gh/abhinavsingh/proxy.py/branch/develop/graph/badge.svg?token=Zh9J7b4la2)](https://codecov.io/gh/abhinavsingh/proxy.py)

[![Contributions Welcome](https://img.shields.io/static/v1?label=Contributions&message=Welcome%20%F0%9F%91%8D&color=darkgreen)](https://github.com/abhinavsingh/proxy.py/issues)
[![Need Help](https://img.shields.io/static/v1?label=Need%20Help%3F&message=Ask&color=darkgreen)](https://twitter.com/imoracle)
[![Sponsored by Jaxl Innovations Private Limited](https://img.shields.io/static/v1?label=Sponsored%20By&message=Jaxl%20Innovations%20Private%20Limited&color=darkgreen)](https://github.com/jaxl-innovations-private-limited)

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
    - [CloudflareDnsResolverPlugin](#cloudflarednsresolverplugin)
    - [CustomDnsResolverPlugin](#customdnsresolverplugin)
    - [CustomNetworkInterface](#customnetworkinterface)
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
  - [Ephemeral Port](#ephemeral-port)
  - [Loading Plugins](#loading-plugins)
- [Unit testing with proxy.py](#unit-testing-with-proxypy)
  - [`proxy.TestCase`](#proxytestcase)
  - [Override Startup Flags](#override-startup-flags)
  - [With `unittest.TestCase`](#with-unittesttestcase)
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
- [Run Dashboard](#run-dashboard)
  - [Inspect Traffic](#inspect-traffic)
- [Chrome DevTools Protocol](#chrome-devtools-protocol)
- [Frequently Asked Questions](#frequently-asked-questions)
  - [Stable vs Develop](#stable-vs-develop)
    - [Release Schedule](#release-schedule)
  - [Threads vs Threadless](#threads-vs-threadless)
  - [SyntaxError: invalid syntax](#syntaxerror-invalid-syntax)
  - [Unable to load plugins](#unable-to-load-plugins)
  - [Unable to connect with proxy.py from remote host](#unable-to-connect-with-proxypy-from-remote-host)
  - [Basic auth not working with a browser](#basic-auth-not-working-with-a-browser)
  - [Docker image not working on MacOS](#docker-image-not-working-on-macos)
  - [`ValueError: filedescriptor out of range in select`](#valueerror-filedescriptor-out-of-range-in-select)
  - [None:None in access logs](#nonenone-in-access-logs)
  - [OSError when wrapping client for TLS Interception](#oserror-when-wrapping-client-for-tls-interception)
- [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
  - [High level architecture](#high-level-architecture)
  - [Everything is a plugin](#everything-is-a-plugin)
  - [Internal Documentation](#internal-documentation)
  - [Development Guide](#development-guide)
    - [Setup Local Environment](#setup-local-environment)
    - [Setup Git Hooks](#setup-git-hooks)
    - [Sending a Pull Request](#sending-a-pull-request)
- [Benchmarks](#benchmarks)
- [Flags](#flags)
- [Changelog](https://proxypy.rtfd.io/en/latest/changelog)
  - [v2.x](https://proxypy.rtfd.io/en/latest/changelog#v2x)
  - [v1.x](https://proxypy.rtfd.io/en/latest/changelog#v1x)
  - [v0.x](https://proxypy.rtfd.io/en/latest/changelog#v0x)

[//]: # (DO-NOT-REMOVE-docs-badges-END)

# Features
- Fast & Scalable

  - Scales by using all available cores on the system
  - Threadless executions using asyncio
  - Made to handle `tens-of-thousands` connections / sec

    ```console
    # On Macbook Pro 2019 / 2.4 GHz 8-Core Intel Core i9 / 32 GB RAM
    ❯ ./helper/benchmark.sh
      CONCURRENCY: 100 workers, TOTAL REQUESTS: 100000 req

      Summary:
        Success rate:	1.0000
        Total:	2.5489 secs
        Slowest:	0.0443 secs
        Fastest:	0.0006 secs
        Average:	0.0025 secs
        Requests/sec:	39232.6572

        Total data:	1.81 MiB
        Size/request:	19 B
        Size/sec:	727.95 KiB

      Response time histogram:
        0.001 [5006]  |■■■■■
        0.001 [19740] |■■■■■■■■■■■■■■■■■■■■■
        0.002 [29701] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
        0.002 [21278] |■■■■■■■■■■■■■■■■■■■■■■
        0.003 [15376] |■■■■■■■■■■■■■■■■
        0.004 [6644]  |■■■■■■■
        0.004 [1609]  |■
        0.005 [434]   |
        0.006 [83]    |
        0.006 [29]    |
        0.007 [100]   |

      Latency distribution:
        10% in 0.0014 secs
        25% in 0.0018 secs
        50% in 0.0023 secs
        75% in 0.0030 secs
        90% in 0.0036 secs
        95% in 0.0040 secs
        99% in 0.0047 secs

      Details (average, fastest, slowest):
        DNS+dialup:	0.0025 secs, 0.0015 secs, 0.0030 secs
        DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0001 secs

      Status code distribution:
        [200] 100000 responses
    ```

  - See [Benchmark](https://github.com/abhinavsingh/proxy.py/tree/develop/benchmark#readme) for more details and how to run them locally.

- Lightweight
  - Uses `~5-20 MB` RAM
  - Compressed containers size is `~18.04 MB`
  - No external dependency other than standard Python library
- Programmable
  - Customize proxy behavior using [Proxy Server Plugins](#http-proxy-plugins). Example:
    - `--plugins proxy.plugin.ProxyPoolPlugin`
  - Optionally, enable builtin [Web Server Plugins](#http-web-server-plugins). Example:
    - `--plugins proxy.plugin.ReverseProxyPlugin`
  - Plugin API is currently in development phase, expect breaking changes
- Real-time Dashboard
  - Optionally, enable [proxy.py dashboard](#run-dashboard).
    - Available at `http://localhost:8899/dashboard`.
  - [Inspect, Monitor, Control and Configure](#inspect-traffic) `proxy.py` at runtime
  - [Chrome DevTools Protocol](#chrome-devtools-protocol) support
  - Extend dashboard using plugins
  - Dashboard is currently in development phase, expect breaking changes
- Secure
  - Enable end-to-end encryption between clients and `proxy.py`
  - See [End-to-End Encryption](#end-to-end-encryption)
- Private
  - Everyone deserves privacy. Browse with malware and adult content protection
  - See [DNS-over-HTTPS](#cloudflarednsresolverplugin)
- Man-In-The-Middle
  - Can decrypt TLS traffic between clients and upstream servers
  - See [TLS Interception](#tls-interception)
- Supported proxy protocols
  - `http(s)`
    - `http1`
    - `http1.1` with pipeline
  - `http2`
  - `websockets`
- Support for `HAProxy Protocol`
  - See `--enable-proxy-protocol` flag
- Static file server support
  - See `--enable-static-server` and `--static-server-dir` flags
- Optimized for large file uploads and downloads
  - See `--client-recvbuf-size` and `--server-recvbuf-size` flag
- `IPv4` and `IPv6` support
  - See `--hostname` flag
- Unix domain socket support
  - See `--unix-socket-path` flag
- Basic authentication support
  - See `--basic-auth` flag
- PAC (Proxy Auto-configuration) support
  - See `--pac-file` and `--pac-file-url-path` flags

# Install

## Using PIP

### Stable Version with PIP

Install from `PyPi`

```console
❯ pip install --upgrade proxy.py
```

or from GitHub `master` branch

```console
❯ pip install git+https://github.com/abhinavsingh/proxy.py.git@master
```

### Development Version with PIP

```console
❯ pip install git+https://github.com/abhinavsingh/proxy.py.git@develop
```

## Using Docker

Stable version container releases are available for following platforms:

- `linux/386`
- `linux/amd64`
- `linux/arm/v6`
- `linux/arm/v7`
- `linux/arm64/v8`
- `linux/ppc64le`
- `linux/s390x`

### Stable Version from Docker Hub

Run `proxy.py` latest container:

```console
❯ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest
```

To run specific target platform container on multi-platform supported servers:

```console
❯ docker run -it -p 8899:8899 --rm --platform linux/arm64/v8 abhinavsingh/proxy.py:latest
```

### Build Development Version Locally

```console
❯ git clone https://github.com/abhinavsingh/proxy.py.git
❯ cd proxy.py && make container
❯ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py:latest
```

[![WARNING](https://img.shields.io/static/v1?label=MacOS&message=warning&color=red)](https://github.com/moby/vpnkit/issues/469)
`docker` image is currently broken on `macOS` due to incompatibility with [vpnkit](https://github.com/moby/vpnkit/issues/469).

## Using HomeBrew

Updated formulae for `HomeBrew` are maintained in `develop` branch under the `helper/homebrew` directory.

- `stable` formulae installs the package from `master` branch.
- `develop` formulae installs the package from `develop` branch.

### Stable Version with HomeBrew

```console
❯ brew install https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/helper/homebrew/stable/proxy.rb
```

### Development Version with HomeBrew

```console
❯ brew install https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/helper/homebrew/develop/proxy.rb
```

# Start proxy.py

## From command line when installed using PIP

When `proxy.py` is installed using `pip`,
an executable named `proxy` is placed under your `$PATH`.

### Run it

Simply type `proxy` on command line to start with default configuration.

```console
❯ proxy
...[redacted]... - Loaded plugin proxy.http.proxy.HttpProxyPlugin
...[redacted]... - Started 8 threadless workers
...[redacted]... - Started 8 acceptors
...[redacted]... - Listening on 127.0.0.1:8899
```

### Understanding logs

Things to notice from above logs:

- `Loaded plugin`
  - `proxy.py` will load `proxy.http.proxy.HttpProxyPlugin` by default
  - As name suggests, this core plugin adds `http(s)` proxy server capabilities to `proxy.py` instance

- `Started N threadless workers`
  - By default, `proxy.py` will start as many worker processes as there are CPU cores on the machine
  - Use `--num-workers` flag to customize number of worker processes
  - See [Threads vs Threadless](#threads-vs-threadless) to understand how to control execution mode

- `Started N acceptors`
  - By default, `proxy.py` will start as many acceptor processes as there are CPU cores on the machine
  - Use `--num-acceptors` flag to customize number of acceptor processes
  - See [High Level Architecture](#high-level-architecture) to understand relationship between acceptors and workers

- `Started server on ::1:8899`
  - By default, `proxy.py` listens on IPv6 `::1`, which is equivalent of IPv4 `127.0.0.1`
  - If you want to access `proxy.py` from external host, use `--hostname ::` or `--hostname 0.0.0.0` or bind to any other interface available on your machine.
  - See [CustomNetworkInterface](#customnetworkinterface) for how to customize `proxy.py` *public IP seen by upstream servers*.

- `Port 8899`
  - Use `--port` flag to customize default TCP port.

### Enable DEBUG logging

All the logs above are `INFO` level logs, default `--log-level` for `proxy.py`

Lets start `proxy.py` with `DEBUG` level logging:

```console
❯ proxy --log-level d
...[redacted]... - Open file descriptor soft limit set to 1024
...[redacted]... - Loaded plugin proxy.http_proxy.HttpProxyPlugin
...[redacted]... - Started 8 workers
...[redacted]... - Started server on ::1:8899
```

You can use single letter to customize log level.  Example:
- `d = DEBUG`
- `i = INFO`
- `w = WARNING`
- `e = ERROR`
- `c = CRITICAL`

As we can see from the above logs, before starting up:

- `proxy.py` tried to set open file limit `ulimit` on the system
- Default value for `--open-file-limit` used is `1024`
- `--open-file-limit` flag is a no-op on `Windows` operating systems

See [flags](#flags) for full list of available configuration options.

## From command line using repo source

If you are trying to run `proxy.py` from source code,
there is no binary file named `proxy` in the source code.

To start `proxy.py` from source code follow these instructions:

- Clone repo

  ```console
  ❯ git clone https://github.com/abhinavsingh/proxy.py.git
  ❯ cd proxy.py
  ```

- Create a Python 3 virtual env

  ```console
  ❯ python3 -m venv venv
  ❯ source venv/bin/activate
  ```

- Install deps

  ```console
  ❯ make lib-dep
  ```

- Generate `proxy/common/_scm_version.py`

  NOTE: *Following step is not necessary for editable installs.*

  This file writes SCM detected version to `proxy/common/_scm_version.py` file.

  ```console
  ❯ ./write-scm-version.sh
  ```

- Optionally, run tests

  ```console
  ❯ make
  ```

- Run `proxy.py`

  ```console
  ❯ python -m proxy
  ```

See [Plugin Developer and Contributor Guide](#plugin-developer-and-contributor-guide)
if you plan to work with `proxy.py` source code.

## Docker image

### Customize startup flags

By default `docker` binary is started with IPv4 networking flags:

    --hostname 0.0.0.0 --port 8899

You can override flag from command line when starting the docker container. For example, to check `proxy.py` version within the docker container, run:

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

[![Shortlink Plugin](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/shortlink.gif)](https://github.com/abhinavsingh/proxy.py#user-content-shortlinkplugin)

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.ShortLinkPlugin
```

Now you can speed up your daily browsing experience by visiting your
favorite website using single character domain names :). This works
across all browsers.

Following short links are enabled by default:

| Short Link |  Destination URL   |
| :--------: |  :--------------:  |
|     a/     |    `amazon.com`    |
|     i/     |  `instagram.com`   |
|     l/     |   `linkedin.com`   |
|     f/     |   `facebook.com`   |
|     g/     |    `google.com`    |
|     t/     |   `twitter.com`    |
|     w/     | `web.whatsapp.com` |
|     y/     |   `youtube.com`    |
|   proxy/   |  `localhost:8899`  |

### ModifyPostDataPlugin

Modifies POST request body before sending request to upstream server.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.ModifyPostDataPlugin
```

By default plugin replaces POST body content with hard-coded `b'{"key": "modified"}'`
and enforced `Content-Type: application/json`.

Verify the same using `curl -x localhost:8899 -d '{"key": "value"}' http://httpbin.org/post`

```console
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

```console
❯ proxy \
    --plugins proxy.plugin.ProposedRestApiPlugin
```

Verify mock API response using `curl -x localhost:8899 http://api.example.com/v1/users/`

```console
{"count": 2, "next": null, "previous": null, "results": [{"email": "you@example.com", "groups": [], "url": "api.example.com/v1/users/1/", "username": "admin"}, {"email": "someone@example.com", "groups": [], "url": "api.example.com/v1/users/2/", "username": "admin"}]}
```

Verify the same by inspecting `proxy.py` logs:

```console
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

```console
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
By default, plugin drops traffic for `facebook.com` and `www.facebok.com`.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.FilterByUpstreamHostPlugin
```

Verify using `curl -v -x localhost:8899 http://facebook.com`:

```console
... [redacted] ...
< HTTP/1.1 418 I'm a tea pot
< Proxy-agent: proxy.py v1.0.0
* no chunk, no close, no size. Assume close to signal end
<
* Closing connection 0
```

Above `418 I'm a tea pot` is sent by our plugin.

Verify the same by inspecting logs for `proxy.py`:

```console
2019-09-24 19:21:37,893 - ERROR - pid:50074 - handle_readables:1347 - HttpProtocolException type raised
Traceback (most recent call last):
... [redacted] ...
2019-09-24 19:21:37,897 - INFO - pid:50074 - access_log:1157 - ::1:49911 - GET None:None/ - None None - 0 bytes
```

### CacheResponsesPlugin

Caches Upstream Server Responses.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.CacheResponsesPlugin
```

Verify using `curl -v -x localhost:8899 http://httpbin.org/get`:

```console
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

```console
... [redacted] ... - GET httpbin.org:80/get - 200 OK - 556 bytes
... [redacted] ... - Cached response at /var/folders/k9/x93q0_xn1ls9zy76m2mf2k_00000gn/T/httpbin.org-1569378301.407512.txt
```

Verify contents of the cache file `cat /path/to/your/cache/httpbin.org.txt`

```console
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

```console
❯ proxy \
    --plugins proxy.plugin.ManInTheMiddlePlugin
```

Verify using `curl -v -x localhost:8899 http://google.com`:

```console
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

Let's start upstream proxies first.

Start `proxy.py` on port `9000` and `9001`

```console
❯ proxy --port 9000
```

```console
❯ proxy --port 9001
```

Now, start `proxy.py` with `ProxyPoolPlugin` (on default `8899` port),
pointing to our upstream proxies at `9000` and `9001` port.

```console
❯ proxy \
    --plugins proxy.plugin.ProxyPoolPlugin \
    --proxy-pool localhost:9000 \
    --proxy-pool localhost:9001
```

Make a curl request via `8899` proxy:

`curl -v -x localhost:8899 http://httpbin.org/get`

Verify that `8899` proxy forwards requests to upstream proxies
by checking respective logs.

### FilterByClientIpPlugin

Reject traffic from specific IP addresses. By default this
plugin blocks traffic from `127.0.0.1` and `::1`.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.FilterByClientIpPlugin
```

Send a request using `curl -v -x localhost:8899 http://google.com`:

```console
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

This plugin demonstrate how to modify chunked encoded responses. In able to do so, this plugin uses `proxy.py` core to parse the chunked encoded response. Then we reconstruct the response using custom hard-coded chunks, ignoring original chunks received from upstream server.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.ModifyChunkResponsePlugin
```

Verify using `curl -v -x localhost:8899 http://httpbin.org/stream/5`:

```console
... [redacted] ...
modify
chunk
response
plugin
* Connection #0 to host localhost left intact
* Closing connection 0
```

Modify `ModifyChunkResponsePlugin` to your taste. Example, instead of sending hard-coded chunks, parse and modify the original `JSON` chunks received from the upstream server.

### CloudflareDnsResolverPlugin

This plugin uses `Cloudflare` hosted `DNS-over-HTTPS` [API](https://developers.cloudflare.com/1.1.1.1/encrypted-dns/dns-over-https/make-api-requests/dns-json) (json).

`DoH` mandates a HTTP2 compliant client. Unfortunately `proxy.py`
does not provide that yet, so we use a dependency. Install it:

```console
❯ pip install "httpx[http2]"
```

Now start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.CloudflareDnsResolverPlugin
```

By default, `CloudflareDnsResolverPlugin` runs in `security` mode and provides malware protection.
Use `--cloudflare-dns-mode family` to also enable adult content protection too.

### CustomDnsResolverPlugin

This plugin demonstrate how to use a custom DNS resolution implementation with `proxy.py`.
This example plugin currently uses Python's in-built resolution mechanism.  Customize code
to your taste.  Example, query your custom DNS server, implement `DoH` or other mechanisms.

Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.CustomDnsResolverPlugin
```

### CustomNetworkInterface

`HttpProxyBasePlugin.resolve_dns` callback can also be used to configure `network interface` which must be used as the `source_address` for connection to the upstream server.

See [this thread](https://github.com/abhinavsingh/proxy.py/issues/535#issuecomment-961510862)
for more details.

PS: There is no plugin named, but [CustomDnsResolverPlugin](#customdnsresolverplugin)
can be easily customized according to your needs.

## HTTP Web Server Plugins

### Reverse Proxy

Extend in-built Web Server to add Reverse Proxy capabilities.

Start `proxy.py` as:

```console
❯ proxy --enable-web-server \
    --plugins proxy.plugin.ReverseProxyPlugin
```

With default configuration, `ReverseProxyPlugin` plugin is equivalent to
following `Nginx` config:

```console
location /get {
    proxy_pass http://httpbin.org/get
}
```

Verify using `curl -v localhost:8899/get`:

```console
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

```console
❯ proxy --enable-web-server \
    --plugins proxy.plugin.WebServerPlugin
```

Verify using `curl -v localhost:8899/http-route-example`, should return:

```console
HTTP route response
```

## Plugin Ordering

When using multiple plugins, depending upon plugin functionality,
it might be worth considering the order in which plugins are passed
on the command line.

Plugins are called in the same order as they are passed. Example,
say we are using both `FilterByUpstreamHostPlugin` and
`RedirectToCustomServerPlugin`. Idea is to drop all incoming `http`
requests for `facebook.com` and `www.facebook.com` and redirect other
`http` requests to our inbuilt web server.

Hence, in this scenario it is important to use
`FilterByUpstreamHostPlugin` before `RedirectToCustomServerPlugin`.
If we enable `RedirectToCustomServerPlugin` before `FilterByUpstreamHostPlugin`,
`facebook` requests will also get redirected to inbuilt web server,
instead of being dropped.

# End-to-End Encryption

By default, `proxy.py` uses `http` protocol for communication with clients e.g. `curl`, `browser`. For enabling end-to-end encrypting using `tls` / `https` first generate certificates. **Checkout** the repository and run:

```console
make https-certificates
```

Start `proxy.py` as:

```console
❯ proxy \
    --cert-file https-cert.pem \
    --key-file https-key.pem
```

Verify using `curl -x https://localhost:8899 --proxy-cacert https-cert.pem https://httpbin.org/get`:

```console
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

```console
make ca-certificates
```

Then, sign SSL certificate:

```console
make sign-https-certificates
```

Now restart the server with `--cert-file https-signed-cert.pem` flag. Note that you must also trust generated `ca-cert.pem` in your system keychain.

# TLS Interception

By default, `proxy.py` will not decrypt `https` traffic between client and server.
To enable TLS interception first generate root CA certificates:

```console
❯ make ca-certificates
```

Lets also enable `CacheResponsePlugin` so that we can verify decrypted
response from the server. Start `proxy.py` as:

```console
❯ proxy \
    --plugins proxy.plugin.CacheResponsesPlugin \
    --ca-key-file ca-key.pem \
    --ca-cert-file ca-cert.pem \
    --ca-signing-key-file ca-signing-key.pem
```

[![NOTE](https://img.shields.io/static/v1?label=MacOS&message=note&color=yellow)](https://github.com/abhinavsingh/proxy.py#user-content-flags) Also provide explicit CA bundle path needed for validation of peer certificates. See `--ca-file` flag.

Verify TLS interception using `curl`

```console
❯ curl -v -x localhost:8899 --cacert ca-cert.pem https://httpbin.org/get
```

```console
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

```console
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

- For security reasons, `proxy.py` docker container does not ship with
  CA certificates.

Here is how to start a `proxy.py` docker container
with TLS Interception:

1. Generate CA certificates on host computer

   ```console
   ❯ make ca-certificates
   ```

2. Copy all generated certificates into a separate directory. We'll later mount this directory into our docker container

   ```console
   ❯ mkdir /tmp/ca-certificates
   ❯ cp ca-cert.pem ca-key.pem ca-signing-key.pem /tmp/ca-certificates
   ```

3. Start docker container

   ```console
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

   ```console
   ❯ curl -v \
       --cacert ca-cert.pem \
       -x 127.0.0.1:8899 \
       https://httpbin.org/get
   ```

5. Verify `issuer` field from response headers.

   ```console
   * Server certificate:
   *  subject: CN=httpbin.org; C=NA; ST=Unavailable; L=Unavailable; O=Unavailable; OU=Unavailable
   *  start date: Jun 17 09:26:57 2020 GMT
   *  expire date: Jun 17 09:26:57 2022 GMT
   *  subjectAltName: host "httpbin.org" matched cert's "httpbin.org"
   *  issuer: CN=example.com
   *  SSL certificate verify ok.
   ```

6. Back on docker terminal, copy response dump path logs.

   ```console
   ...[redacted]... [I] access_log:338 - 172.17.0.1:56498 - CONNECT httpbin.org:443 - 1031 bytes - 1216.70 ms
   ...[redacted]... [I] close:49 - Cached response at /tmp/httpbin.org-ae1a927d064e4ab386ea319eb38fe251.txt
   ```

7. In another terminal, `cat` the response dump:

   ```console
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

Requires `paramiko` to work.

See [requirements-tunnel.txt](https://github.com/abhinavsingh/proxy.py/blob/develop/requirements-tunnel.txt)

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

```console
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

```console
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

```console
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
by using `Proxy` context manager: Example:

```python
import proxy

if __name__ == '__main__':
  with proxy.Proxy([]) as p:
    # ... your logic here ...
```

Note that:

1. `Proxy` is similar to `main`, except `Proxy` does not block.
2. Internally `Proxy` is a context manager.
3. It will start `proxy.py` when called and will shut it down
   once the scope ends.
4. Just like `main`, startup flags with `Proxy`
   can be customized by either passing flags as list of
   input arguments e.g. `Proxy(['--port', '8899'])` or
   by using passing flags as kwargs e.g. `Proxy(port=8899)`.

## Ephemeral Port

Use `--port=0` to bind `proxy.py` on a random port allocated by the kernel.

In embedded mode, you can access this port.  Example:

```python
import proxy

if __name__ == '__main__':
  with proxy.Proxy([]) as p:
    print(p.flags.port)
```

`flags.port` will give you access to the random port allocated by the kernel.

## Loading Plugins

Users can use `--plugins` flag multiple times to load multiple plugins.
See [Unable to load plugins](#unable-to-load-plugins) if you are running into issues.

When using in embedded mode, you have a few more options.  Example:

1. Provide a fully-qualified name of the plugin class as `bytes` to the `proxy.main` method or `proxy.Proxy` context manager.
2. Provide `type` instance of the plugin class. This is especially useful if you plan to define plugins at runtime.

Example, load a single plugin using `--plugins` flag:

```python
import proxy

if __name__ == '__main__':
  proxy.main([
    '--plugins', 'proxy.plugin.CacheResponsesPlugin',
  ])
```

For simplicity, you can also pass the list of plugins as a keyword argument to `proxy.main` or the `Proxy` constructor.

Example:

```python
import proxy
from proxy.plugin import FilterByUpstreamHostPlugin

if __name__ == '__main__':
  proxy.main([], plugins=[
    b'proxy.plugin.CacheResponsesPlugin',
    FilterByUpstreamHostPlugin,
  ])
```

# Unit testing with proxy.py

## `proxy.TestCase`

To setup and tear down `proxy.py` for your Python `unittest` classes,
simply use `proxy.TestCase` instead of `unittest.TestCase`.
Example:

```python
import proxy

class TestProxyPyEmbedded(proxy.TestCase):

    def test_my_application_with_proxy(self) -> None:
        self.assertTrue(True)
```

Note that:

1. `proxy.TestCase` overrides `unittest.TestCase.run()` method to setup and tear down `proxy.py`.
2. `proxy.py` server will listen on a random available port on the system.
   This random port is available as `self.PROXY.flags.port` within your test cases.
3. Only a single acceptor and worker is started by default (`--num-workers 1 --num-acceptors 1`) for faster setup and tear down.
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
        '--num-workers', '2',
        '--num-acceptors', '1',
        '--enable-web-server',
    ]

    def test_my_application_with_proxy(self) -> None:
        self.assertTrue(True)
```

See [test_embed.py] for full working example.

[test_embed.py]:
https://github.com/abhinavsingh/proxy.py/blob/develop/tests/testing/test_embed.py

## With `unittest.TestCase`

If for some reasons you are unable to directly use `proxy.TestCase`,
then simply override `unittest.TestCase.run` yourself to setup and tear down `proxy.py`.
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
                '--num-acceptors', '1',
                '--port', '... random port ...']):
            super().run(result)
```

or simply setup / tear down `proxy.py` within
`setUpClass` and `teardownClass` class methods.

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

## HTTP Client

### build_http_request

- Generate HTTP GET request

  ```python
  >>> build_http_request(b'GET', b'/')
  b'GET / HTTP/1.1\r\n\r\n'
  ```

- Generate HTTP GET request with headers

  ```python
  >>> build_http_request(b'GET', b'/',
          headers={b'Connection': b'close'})
  b'GET / HTTP/1.1\r\nConnection: close\r\n\r\n'
  ```

- Generate HTTP POST request with headers and body

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

- `gen_private_key`

  ```python
  gen_private_key(
      key_path: str,
      password: str,
      bits: int = 2048,
      timeout: int = 10) -> bool
  ```

- `gen_public_key`

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

- `remove_passphrase`

  ```python
  remove_passphrase(
      key_in_path: str,
      password: str,
      key_out_path: str,
      timeout: int = 10) -> bool
  ```

- `gen_csr`

  ```python
  gen_csr(
      csr_path: str,
      key_path: str,
      password: str,
      crt_path: str,
      timeout: int = 10) -> bool
  ```

- `sign_csr`

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

```console
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

Code is well documented. You have a few options to browse the internal class hierarchy and documentation:

1. Visit [proxypy.readthedocs.io](https://proxypy.readthedocs.io/)
2. Build and open docs locally using `make lib-doc`
2. Use `pydoc3` locally using `pydoc3 proxy`

# Run Dashboard

Dashboard is currently under development and not yet bundled with `pip` packages.
To run dashboard, you must checkout the source.

Dashboard is written in Typescript and SCSS, so let's build it first using:

```console
❯ make dashboard
```

Also build the embedded `Chrome DevTools` if you plan on using it:

```console
❯ make devtools
```

Now start `proxy.py` with dashboard plugin and by overriding root directory for static server:

```console
❯ proxy --enable-dashboard --static-server-dir dashboard/public
...[redacted]... - Loaded plugin proxy.http.server.HttpWebServerPlugin
...[redacted]... - Loaded plugin proxy.dashboard.dashboard.ProxyDashboard
...[redacted]... - Loaded plugin proxy.dashboard.inspect_traffic.InspectTrafficPlugin
...[redacted]... - Loaded plugin proxy.http.inspector.DevtoolsProtocolPlugin
...[redacted]... - Loaded plugin proxy.http.proxy.HttpProxyPlugin
...[redacted]... - Listening on ::1:8899
...[redacted]... - Core Event enabled
```

Currently, enabling dashboard will also enable all the dashboard plugins.

Visit dashboard:

```console
❯ open http://localhost:8899/dashboard/
```

## Inspect Traffic

***This is a WIP and may not work as documented***

Wait for embedded `Chrome Dev Console` to load.  Currently, detail about all traffic flowing
through `proxy.py` is pushed to the `Inspect Traffic` tab.  However, received payloads are not
yet integrated with the embedded developer console.

Current functionality can be verified by opening the `Dev Console` of dashboard and inspecting
the websocket connection that dashboard established with the `proxy.py` server.

[![Proxy.Py Dashboard Inspect Traffic](https://raw.githubusercontent.com/abhinavsingh/proxy.py/develop/Dashboard.png)](https://github.com/abhinavsingh/proxy.py)

# Chrome DevTools Protocol

For scenarios where you want direct access to `Chrome DevTools` protocol websocket endpoint,
start `proxy.py` as:

```console
❯ proxy --enable-devtools --enable-events
```

Now point your CDT instance to `ws://localhost:8899/devtools`.

# Frequently Asked Questions

## Stable vs Develop

- `master` branch contains latest `stable` code and is available via `PyPi` repository and `Docker` containers via `hub.docker.com`

  Issues reported for `stable` releases are considered with top-priority.  However, currently we don't back port fixes into older releases.  Example, if you reported an issue in `v2.3.1`, but current `master` branch now contains `v2.4.0rc1`.  Then, the fix will land in `v2.4.0rc2`.

- `develop` branch contains cutting edge changes

  Development branch is kept stable *(most of the times)*. **But**, if you want *100% reliability* and serving users in *production environment*, ALWAYS use the stable version.

### Release Schedule

A `vX.Y.ZrcN` pull request is created once a month which merges `develop` → `master`.  Find below how code flows from a pull request to the next stable release.

1. Development release is deployed from `develop` → `test.pypi.org` after every pull request merge

2. Alpha release is deployed from `develop` → `pypi.org` **before** merging the `vX.Y.Z.rcN` pull request from `develop` → `master` branch.  There can be multiple alpha releases made before merging the `rc` pull request

3. Beta release is deployed from `master` → `pypi.org`.  Beta releases are made in preparation of `rc` releases and can be skipped if unnecessary

4. Release candidate is deployed from `master` → `pypi.org`.  Release candidates are always made available before final stable release

5. Stable release is deployed from `master` → `pypi.org`

## Threads vs Threadless

### `v1.x`

`proxy.py` used to spawn new threads for handling client requests.

### `v2.0+`

`proxy.py` added support for threadless execution of client requests using `asyncio`.

### `v2.4.0+`

Threadless execution was turned ON by default for `Python 3.8+` on `mac` and `linux` environments.

`proxy.py` threadless execution has been reported safe on these environments by our users. If you are running into trouble, fallback to threaded mode using `--threaded` flag.

For `windows` and `Python < 3.8`, you can still try out threadless mode by starting `proxy.py` with `--threadless` flag.

If threadless works for you, consider sending a PR by editing `_env_threadless_compliant` method in the `proxy/common/constants.py` file.

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

```console
...[redacted]... - Loaded plugin proxy.HttpProxyPlugin
...[redacted]... - Loaded plugin my_app.proxyPlugin
```

OR, simply pass fully-qualified path as parameter, e.g.

`proxy --plugins /path/to/my/app/my_app.proxyPlugin`

Here is a quick working example:

- Contents of `/tmp/plug` folder

```console
╰─ ls -1 /tmp/plug                                                                                                                       ─╯
my_plugin.py
```

- Custom `MyPlugin` class

```console
╰─ cat /tmp/plug/my_plugin.py                                                                                                            ─╯
from proxy.http.proxy import HttpProxyBasePlugin


class MyPlugin(HttpProxyBasePlugin):
  pass
```

This is an empty plugin for demonstrating external plugin usage. You must implement necessary methods to make your plugins work for real traffic

- Start `proxy.py` with `MyPlugin`

```console
╰─ PYTHONPATH=/tmp/plug proxy --plugin my_plugin.MyPlugin                                                                      ─╯
...[redacted]... - Loaded plugin proxy.http.proxy.HttpProxyPlugin
...[redacted]... - Loaded plugin my_plugin.MyPlugin
...[redacted]... - Listening on ::1:8899
```

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

A starter [fluentd.conf](https://github.com/abhinavsingh/proxy.py/blob/develop/helper/fluentd.conf)
template is available.

1. Copy this configuration file as `proxy.py.conf` under
   `/etc/google-fluentd/config.d/`

2. Update `path` field to log file path as used with `--log-file` flag.
   By default `/tmp/proxy.log` path is tailed.

3. Reload `google-fluentd`:

   `sudo service google-fluentd restart`

Now `proxy.py` logs can be browsed using
[GCE log viewer](https://console.cloud.google.com/logs/viewer).

## `ValueError: filedescriptor out of range in select`

`proxy.py` is made to handle thousands of connections per second
without any socket leaks.

1. Make use of `--open-file-limit` flag to customize `ulimit -n`.
2. Make sure to adjust `--backlog` flag for higher concurrency.

If nothing helps, [open an issue](https://github.com/abhinavsingh/proxy.py/issues/new)
with `requests per second` sent and output of following debug script:

```console
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

## OSError when wrapping client for TLS Interception

With `TLS Interception` on, you might occasionally see following exceptions:

```console
2021-11-06 23:33:34,540 - pid:91032 [E] server.intercept:678 - OSError when wrapping client
Traceback (most recent call last):
  ...[redacted]...
  ...[redacted]...
  ...[redacted]...
ssl.SSLError: [SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca (_ssl.c:997)
...[redacted]... - CONNECT oauth2.googleapis.com:443 - 0 bytes - 272.08 ms
```

Some clients can throw `TLSV1_ALERT_UNKNOWN_CA` if they cannot verify the certificate of the server
because it is signed by an unknown issuer CA.  Which is the case when we are doing TLS interception.
This can be for a variety of reasons e.g. certificate pinning etc.

Another exception you might see is `CERTIFICATE_VERIFY_FAILED`:

```console
2021-11-06 23:36:02,002 - pid:91033 [E] handler.handle_readables:293 - Exception while receiving from client connection <socket.socket fd=28, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 8899), raddr=('127.0.0.1', 51961)> with reason SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate in certificate chain (_ssl.c:997)')
Traceback (most recent call last):
  ...[redacted]...
  ...[redacted]...
  ...[redacted]...
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate in certificate chain (_ssl.c:997)
...[redacted]... - CONNECT init.push.apple.com:443 - 0 bytes - 892.99 ms
```

In future, we might support serving original HTTPS content for such clients while still
performing TLS interception in the background.  This will keep the clients happy without
impacting our ability to TLS intercept.  Unfortunately, this feature is currently not available.

Another example with `SSLEOFError` exception:

```console
2021-11-06 23:46:40,446 - pid:91034 [E] server.intercept:678 - OSError when wrapping client
Traceback (most recent call last):
  ...[redacted]...
  ...[redacted]...
  ...[redacted]...
ssl.SSLEOFError: EOF occurred in violation of protocol (_ssl.c:997)
...[redacted]... - CONNECT stock.adobe.io:443 - 0 bytes - 685.32 ms
```

# Plugin Developer and Contributor Guide

## High level architecture

```console
                        +-------------+
                        |             |
                        |  Proxy([])  |
                        |             |
                        +------+------+
                               |
                               |
                   +-----------v--------------+
                   |                          |
                   |    AcceptorPool(...)     |
                   |                          |
                   +------------+-------------+
                                |
+-----------------+             |           +-----------------+
|                 |             |           |                 |
|   Acceptor(..)  <-------------+----------->  Acceptor(..)   |
|                 |                         |                 |
+---+-------------+                         +---------+-------+
    |                                                 |
    |                                                 |
    |    +------++------++------++------++------+     |
    |    |      ||      ||      ||      ||      |     |
    +---->      ||      ||      ||      ||      <-----+
         |      ||      ||      ||      ||      |
         +------++------++------++------++------+
                Threadless Worker Processes
```

`proxy.py` is made with performance in mind.  By default, `proxy.py`
will try to utilize all available CPU cores to it for accepting new
client connections. This is achieved by starting `AcceptorPool` which
listens on configured server port. Then, `AcceptorPool` starts `Acceptor`
processes (`--num-acceptors`) to accept incoming client connections.
Alongside, if `--threadless` is enabled, `ThreadlessPool` is setup
which starts `Threadless` processes (`--num-workers`) to handle
the incoming client connections.

Each `Acceptor` process delegates the accepted client connection
to a threadless process via `Work` class.  Currently, `HttpProtocolHandler`
is the default work class.

`HttpProtocolHandler` simply assumes that incoming clients will follow
HTTP specification.  Specific HTTP proxy and HTTP server implementations
are written as plugins of `HttpProtocolHandler`.

See documentation of `HttpProtocolHandlerPlugin` for available lifecycle hooks.
Use `HttpProtocolHandlerPlugin` to add new features for http(s) clients. Example,
See `HttpWebServerPlugin`.

## Everything is a plugin

Within `proxy.py` everything is a plugin.

- We enabled `proxy server` plugins using `--plugins` flag.
  Proxy server `HttpProxyPlugin` is a plugin of `HttpProtocolHandler`.
  Further, Proxy server allows plugin through `HttpProxyBasePlugin` specification.

- All the proxy server [plugin examples](#plugin-examples) were implementing
  `HttpProxyBasePlugin`. See documentation of `HttpProxyBasePlugin` for available
  lifecycle hooks. Use `HttpProxyBasePlugin` to modify behavior of http(s) proxy protocol
  between client and upstream server. Example,
  [FilterByUpstreamHostPlugin](#filterbyupstreamhostplugin).

- We also enabled inbuilt `web server` using `--enable-web-server`.
  Web server `HttpWebServerPlugin` is a plugin of `HttpProtocolHandler`
  and implements `HttpProtocolHandlerPlugin` specification.

- There also is a `--disable-http-proxy` flag. It disables inbuilt proxy server.
  Use this flag with `--enable-web-server` flag to run `proxy.py` as a programmable
  http(s) server.

## Development Guide

### Setup Local Environment

Contributors must start `proxy.py` from source to verify and develop new features / fixes.

See [Run proxy.py from command line using repo source](#from-command-line-using-repo-source) for details.


[![WARNING](https://img.shields.io/static/v1?label=MacOS&message=warning&color=red)](https://github.com/abhinavsingh/proxy.py/issues/642#issuecomment-960819271) On `macOS`
you must install `Python` using `pyenv`, as `Python` installed via `homebrew` tends
to be problematic.  See linked thread for more details.

### Setup Git Hooks

Pre-commit hook ensures tests are passing.

1. `cd /path/to/proxy.py`
2. `ln -s $(PWD)/git-pre-commit .git/hooks/pre-commit`

Pre-push hook ensures lint and tests are passing.

1. `cd /path/to/proxy.py`
2. `ln -s $(PWD)/git-pre-push .git/hooks/pre-push`

### Sending a Pull Request

Every pull request is tested using GitHub actions.

See [GitHub workflow](https://github.com/abhinavsingh/proxy.py/tree/develop/.github/workflows)
for list of tests.

# Benchmarks

See [Benchmark](https://github.com/abhinavsingh/proxy.py/tree/develop/benchmark) directory on how to run benchmark comparisons with other OSS web servers.

To run standalone benchmark for `proxy.py`, use the following command from repo root:

```console
❯ ./helper/benchmark.sh
```

# Flags

```console
❯ proxy -h
usage: -m [-h] [--enable-events] [--enable-conn-pool] [--threadless]
          [--threaded] [--num-workers NUM_WORKERS] [--local-executor]
          [--backlog BACKLOG] [--hostname HOSTNAME] [--port PORT]
          [--unix-socket-path UNIX_SOCKET_PATH]
          [--num-acceptors NUM_ACCEPTORS] [--version] [--log-level LOG_LEVEL]
          [--log-file LOG_FILE] [--log-format LOG_FORMAT]
          [--open-file-limit OPEN_FILE_LIMIT]
          [--plugins PLUGINS [PLUGINS ...]] [--enable-dashboard]
          [--work-klass WORK_KLASS] [--pid-file PID_FILE]
          [--enable-proxy-protocol]
          [--client-recvbuf-size CLIENT_RECVBUF_SIZE] [--key-file KEY_FILE]
          [--timeout TIMEOUT] [--server-recvbuf-size SERVER_RECVBUF_SIZE]
          [--disable-http-proxy] [--disable-headers DISABLE_HEADERS]
          [--ca-key-file CA_KEY_FILE] [--ca-cert-dir CA_CERT_DIR]
          [--ca-cert-file CA_CERT_FILE] [--ca-file CA_FILE]
          [--ca-signing-key-file CA_SIGNING_KEY_FILE] [--cert-file CERT_FILE]
          [--auth-plugin AUTH_PLUGIN] [--basic-auth BASIC_AUTH]
          [--cache-dir CACHE_DIR]
          [--filtered-upstream-hosts FILTERED_UPSTREAM_HOSTS]
          [--enable-web-server] [--enable-static-server]
          [--static-server-dir STATIC_SERVER_DIR]
          [--min-compression-length MIN_COMPRESSION_LENGTH]
          [--pac-file PAC_FILE] [--pac-file-url-path PAC_FILE_URL_PATH]
          [--proxy-pool PROXY_POOL]
          [--filtered-client-ips FILTERED_CLIENT_IPS]
          [--filtered-url-regex-config FILTERED_URL_REGEX_CONFIG]
          [--cloudflare-dns-mode CLOUDFLARE_DNS_MODE]

proxy.py v2.4.0rc2.dev21+g20b3eb1.d20211203

options:
  -h, --help            show this help message and exit
  --enable-events       Default: False. Enables core to dispatch lifecycle
                        events. Plugins can be used to subscribe for core
                        events.
  --enable-conn-pool    Default: False. (WIP) Enable upstream connection
                        pooling.
  --threadless          Default: True. Enabled by default on Python 3.8+ (mac,
                        linux). When disabled a new thread is spawned to
                        handle each client connection.
  --threaded            Default: False. Disabled by default on Python < 3.8
                        and windows. When enabled a new thread is spawned to
                        handle each client connection.
  --num-workers NUM_WORKERS
                        Defaults to number of CPU cores.
  --local-executor      Default: False. Disabled by default. When enabled
                        acceptors will make use of local (same process)
                        executor instead of distributing load across remote
                        (other process) executors. Enable this option to
                        achieve CPU affinity between acceptors and executors,
                        instead of using underlying OS kernel scheduling
                        algorithm.
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --hostname HOSTNAME   Default: ::1. Server IP address.
  --port PORT           Default: 8899. Server port.
  --unix-socket-path UNIX_SOCKET_PATH
                        Default: None. Unix socket path to use. When provided
                        --host and --port flags are ignored
  --num-acceptors NUM_ACCEPTORS
                        Defaults to number of CPU cores.
  --version, -v         Prints proxy.py version.
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
  --plugins PLUGINS [PLUGINS ...]
                        Comma separated plugins. You may use --plugins flag
                        multiple times.
  --enable-dashboard    Default: False. Enables proxy.py dashboard.
  --work-klass WORK_KLASS
                        Default: proxy.http.HttpProtocolHandler. Work klass to
                        use for work execution.
  --pid-file PID_FILE   Default: None. Save "parent" process ID to a file.
  --enable-proxy-protocol
                        Default: False. If used, will enable proxy protocol.
                        Only version 1 is currently supported.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --key-file KEY_FILE   Default: None. Server key file to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --cert-file.
  --timeout TIMEOUT     Default: 10.0. Number of seconds after which an
                        inactive connection must be dropped. Inactivity is
                        defined by no data sent or received by the client.
  --server-recvbuf-size SERVER_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the server in a single recv() operation. Bump this
                        value for faster downloads at the expense of increased
                        RAM.
  --disable-http-proxy  Default: False. Whether to disable
                        proxy.HttpProxyPlugin.
  --disable-headers DISABLE_HEADERS
                        Default: None. Comma separated list of headers to
                        remove before dispatching client request to upstream
                        server.
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
  --ca-file CA_FILE     Default: /Users/abhinavsingh/Dev/proxy.py/venv310/lib/
                        python3.10/site-packages/certifi/cacert.pem. Provide
                        path to custom CA bundle for peer certificate
                        verification
  --ca-signing-key-file CA_SIGNING_KEY_FILE
                        Default: None. CA signing key to use for dynamic
                        generation of HTTPS certificates. If used, must also
                        pass --ca-key-file and --ca-cert-file
  --cert-file CERT_FILE
                        Default: None. Server certificate to enable end-to-end
                        TLS encryption with clients. If used, must also pass
                        --key-file.
  --auth-plugin AUTH_PLUGIN
                        Default: proxy.http.proxy.AuthPlugin. Auth plugin to
                        use instead of default basic auth plugin.
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --cache-dir CACHE_DIR
                        Default: A temporary directory. Flag only applicable
                        when cache plugin is used with on-disk storage.
  --filtered-upstream-hosts FILTERED_UPSTREAM_HOSTS
                        Default: Blocks Facebook. Comma separated list of IPv4
                        and IPv6 addresses.
  --enable-web-server   Default: False. Whether to enable
                        proxy.HttpWebServerPlugin.
  --enable-static-server
                        Default: False. Enable inbuilt static file server.
                        Optionally, also use --static-server-dir to serve
                        static content from custom directory. By default,
                        static file server serves out of installed proxy.py
                        python module folder.
  --static-server-dir STATIC_SERVER_DIR
                        Default: "public" folder in directory where proxy.py
                        is placed. This option is only applicable when static
                        server is also enabled. See --enable-static-server.
  --min-compression-length MIN_COMPRESSION_LENGTH
                        Default: 20 bytes. Sets the minimum length of a
                        response that will be compressed (gzipped).
  --pac-file PAC_FILE   A file (Proxy Auto Configuration) or string to serve
                        when the server receives a direct file request. Using
                        this option enables proxy.HttpWebServerPlugin.
  --pac-file-url-path PAC_FILE_URL_PATH
                        Default: /. Web server path to serve the PAC file.
  --proxy-pool PROXY_POOL
                        List of upstream proxies to use in the pool
  --filtered-client-ips FILTERED_CLIENT_IPS
                        Default: 127.0.0.1,::1. Comma separated list of IPv4
                        and IPv6 addresses.
  --filtered-url-regex-config FILTERED_URL_REGEX_CONFIG
                        Default: No config. Comma separated list of IPv4 and
                        IPv6 addresses.
  --cloudflare-dns-mode CLOUDFLARE_DNS_MODE
                        Default: security. Either "security" (for malware
                        protection) or "family" (for malware and adult content
                        protection)

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```
