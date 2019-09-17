[![Proxy.Py](ProxyPy.png)](https://github.com/abhinavsingh/proxy.py)

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![PyPi Downloads](https://img.shields.io/pypi/dm/proxy.py.svg)](https://pypi.org/project/proxy.py/)
[![Build Status](https://travis-ci.org/abhinavsingh/proxy.py.svg?branch=develop)](https://travis-ci.org/abhinavsingh/proxy.py/)
[![Coverage](https://coveralls.io/repos/github/abhinavsingh/proxy.py/badge.svg?branch=develop)](https://coveralls.io/github/abhinavsingh/proxy.py?branch=develop)

[![Twitter](https://img.shields.io/twitter/follow/imoracle?label=Follow%20on%20Twitter&style=social)](https://twitter.com/imoracle)

Features
--------

- Distributed as a single file module
- No external dependency other than standard Python library
- Support for `http`, `https`, `http2` and `websockets` request proxy
- Optimized for large file uploads and downloads
- IPv4 and IPv6 support
- Basic authentication support
- Can serve a [PAC (Proxy Auto-configuration)](https://en.wikipedia.org/wiki/Proxy_auto-config) file
- Optionally enable builtin Web Server
- Customize proxy and http routing via [plugins](https://github.com/abhinavsingh/proxy.py/blob/develop/plugin_examples.py)

Install
-------

#### Stable version

	$ pip install --upgrade proxy.py

#### Development version

    $ pip install git+https://github.com/abhinavsingh/proxy.py.git@develop

#### Docker image

    $ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py

Usage
-----

```
$ proxy.py -h
usage: proxy.py [-h] [--backlog BACKLOG] [--basic-auth BASIC_AUTH]
                [--client-recvbuf-size CLIENT_RECVBUF_SIZE]
                [--disable-headers DISABLE_HEADERS] [--disable-http-proxy]
                [--hostname HOSTNAME] [--ipv4] [--enable-web-server]
                [--log-level LOG_LEVEL] [--log-file LOG_FILE]
                [--log-format LOG_FORMAT] [--num-workers NUM_WORKERS]
                [--open-file-limit OPEN_FILE_LIMIT] [--pac-file PAC_FILE]
                [--pac-file-url-path PAC_FILE_URL_PATH] [--pid-file PID_FILE]
                [--plugins PLUGINS] [--port PORT]
                [--server-recvbuf-size SERVER_RECVBUF_SIZE] [--version]

proxy.py v1.0.0

optional arguments:
  -h, --help            show this help message and exit
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 1 MB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --disable-headers DISABLE_HEADERS
                        Default: None. Comma separated list of headers to
                        remove before dispatching client request to upstream
                        server.
  --disable-http-proxy  Default: False. Whether to disable
                        proxy.HttpProxyPlugin.
  --hostname HOSTNAME   Default: 127.0.0.1. Server IP address.
  --ipv4                Whether to listen on IPv4 address. By default server
                        only listens on IPv6.
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
  --version, -v         Prints proxy.py version.

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```
