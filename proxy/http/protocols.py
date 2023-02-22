# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       http
       iterable
"""
from typing import NamedTuple


HttpProtocols = NamedTuple(
    'HttpProtocols', [
        ('UNKNOWN', int),
        # Web server handling HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3
        # over plain Text or encrypted connection with clients
        ('WEB_SERVER', int),
        # Proxies handling HTTP/1.0, HTTP/1.1, HTTP/2 protocols
        # over plain text connection or encrypted connection
        # with clients
        ('HTTP_PROXY', int),
        # Proxies handling SOCKS4, SOCKS4a, SOCKS5 protocol
        ('SOCKS_PROXY', int),
    ],
)

httpProtocols = HttpProtocols(1, 2, 3, 4)
