proxy.py
========

Lightweight HTTP, HTTPS and WebSockets Proxy Server in Python.

![alt text](https://travis-ci.org/abhinavsingh/proxy.py.svg?branch=develop "Build Status")

Features
--------

- Distributed as a single file module
- No external dependency other than standard Python library
- Support for `http`, `https` and `websockets` request proxy
- Optimize for large file uploads and downloads
- IPv4 and IPv6 support
- Basic authentication support

Install
-------

To install proxy.py, simply:

	$ pip install --upgrade proxy.py

Usage
-----

```
$ proxy.py -h
usage: proxy.py [-h] [--hostname HOSTNAME] [--port PORT] [--backlog BACKLOG]
                [--basic-auth BASIC_AUTH]
                [--server-recvbuf-size SERVER_RECVBUF_SIZE]
                [--client-recvbuf-size CLIENT_RECVBUF_SIZE]
                [--log-level LOG_LEVEL]

proxy.py v0.3

optional arguments:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   Default: 127.0.0.1
  --port PORT           Default: 8899
  --backlog BACKLOG     Default: 100. Maximum number of pending connections to
                        proxy server
  --basic-auth BASIC_AUTH
                        Default: No authentication. Specify colon separated
                        user:password to enable basic authentication.
  --server-recvbuf-size SERVER_RECVBUF_SIZE
                        Default: 8 KB. Maximum amount of data received from
                        the server in a single recv() operation. Bump this
                        value for faster downloads at the expense of increased
                        RAM.
  --client-recvbuf-size CLIENT_RECVBUF_SIZE
                        Default: 8 KB. Maximum amount of data received from
                        the client in a single recv() operation. Bump this
                        value for faster uploads at the expense of increased
                        RAM.
  --log-level LOG_LEVEL
                        DEBUG, INFO (default), WARNING, ERROR, CRITICAL

Having difficulty using proxy.py? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```
