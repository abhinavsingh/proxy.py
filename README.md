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
- Can serve a PAC (Proxy Autoconfiguration) file

Install
-------

To install proxy.py, simply:

	$ pip install --upgrade proxy.py

Using docker:

    $ docker run -it -p 8899:8899 --rm abhinavsingh/proxy.py

Usage
-----

```
usage: proxy.py [-h] [--hostname HOSTNAME] [--port PORT] [--backlog BACKLOG]
                [--basic-auth BASIC_AUTH]
                [--server-recvbuf-size SERVER_RECVBUF_SIZE]
                [--client-recvbuf-size CLIENT_RECVBUF_SIZE]
                [--open-file-limit OPEN_FILE_LIMIT] [--log-level LOG_LEVEL]
                [--pac-file PAC_FILE] [--ipv4 IPV4]

proxy.py v0.4

optional arguments:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   Default: 127.0.0.1. Server IP address.
  --port PORT           Default: 8899. Server port.
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
  --open-file-limit OPEN_FILE_LIMIT
                        Default: 1024. Maximum number of files (TCP
                        connections) that proxy.py can open concurrently.
  --log-level LOG_LEVEL
                        Valid options: DEBUG, INFO (default), WARNING, ERROR,
                        CRITICAL. Both upper and lowercase values are
                        allowed.You may also simply use the leading character
                        e.g. --log-level d
  --pac-file PAC_FILE   A file (Proxy Auto Configuration) or string to serve
                        when the server receives a direct file request.
  --ipv4 IPV4           Whether to listen on IPv4 address. By default server
                        only listens on IPv6.

Proxy.py not working? Report at:
https://github.com/abhinavsingh/proxy.py/issues/new
```
