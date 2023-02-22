# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       http
       iterable
"""
from typing import NamedTuple


# Ref: https://www.iana.org/assignments/http-methods/http-methods.xhtml
HttpHeaders = NamedTuple(
    'HttpHeaders', [
        ('PROXY_AUTHORIZATION', bytes),
        ('PROXY_CONNECTION', bytes),
    ],
)

httpHeaders = HttpHeaders(
    b'proxy-authorization',
    b'proxy-connection',
)
