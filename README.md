[![Proxy.Py](ProxyPy.png)](https://github.com/abhinavsingh/proxy.py)

[![alt text](https://travis-ci.org/abhinavsingh/proxy.py.svg?branch=develop "Build Status")](https://travis-ci.org/abhinavsingh/proxy.py/)

Features
--------

- Distributed as a single file module
- Optionally enable builtin Web Server
- Customize proxy and http routing via plugins
- No external dependency other than standard Python library
- Support for `http`, `https`, `http2` and `websockets` request proxy
- Optimized for large file uploads and downloads
- IPv4 and IPv6 support
- Basic authentication support
- Can serve a [PAC (Proxy Auto-configuration)](https://en.wikipedia.org/wiki/Proxy_auto-config) file

Install
-------

To install proxy.py, simply:

	$ pip install --upgrade proxy.py

Using docker:

    $ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py

Usage
-----

```
$ proxy.py -h
usage: proxy.py [-h] [--backlog BACKLOG] [--basic-auth BASIC_AUTH]
                [--client-recvbuf-size CLIENT_RECVBUF_SIZE]
                [--hostname HOSTNAME] [--ipv4]
                [--enable-http-proxy ENABLE_HTTP_PROXY]
                [--enable-web-server ENABLE_WEB_SERVER]
                [--log-level LOG_LEVEL] [--log-format LOG_FORMAT]
                [--open-file-limit OPEN_FILE_LIMIT] [--pac-file PAC_FILE]
                [--pac-file-url-path PAC_FILE_URL_PATH] [--plugins PLUGINS]
                [--port PORT] [--server-recvbuf-size SERVER_RECVBUF_SIZE]
                [--num-workers NUM_WORKERS]

proxy.py v0.4

optional arguments:
  -h, --help            show this help message and exit
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 8 KB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --hostname HOSTNAME   Default: 127.0.0.1. Server IP address.
  --ipv4                Whether to listen on IPv4 address. By default server
                        only listens on IPv6.
  --enable-http-proxy ENABLE_HTTP_PROXY
                        Default: True. Whether to enable
                        proxy.HttpProxyPlugin.
  --enable-web-server ENABLE_WEB_SERVER
                        Default: False. Whether to enable
                        proxy.HttpWebServerPlugin.
  --log-level LOG_LEVEL
                        Valid options: DEBUG, INFO (default), WARNING, ERROR,
                        CRITICAL. Both upper and lowercase values are
                        allowed.You may also simply use the leading character
                        e.g. --log-level d
  --log-format LOG_FORMAT
                        Log format for Python logger.
  --open-file-limit OPEN_FILE_LIMIT
                        Default: 1024. Maximum number of files (TCP
                        connections) that proxy.py can open concurrently.
  --pac-file PAC_FILE   A file (Proxy Auto Configuration) or string to serve
                        when the server receives a direct file request.
  --pac-file-url-path PAC_FILE_URL_PATH
                        Web server path to serve the PAC file.
  --plugins PLUGINS     Comma separated plugins
  --port PORT           Default: 8899. Server port.
  --server-recvbuf-size SERVER_RECVBUF_SIZE
                        Default: 8 KB. Maximum amount of data received from
                        the server in a single recv() operation. Bump this
                        value for faster downloads at the expense of increased
                        RAM.
  --num-workers NUM_WORKERS
                        Defaults to number of CPU cores.

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```
