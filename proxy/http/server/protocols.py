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

HttpProtocolTypes = NamedTuple(
    'HttpProtocolTypes', [
        ('HTTP', int),
        ('HTTPS', int),
        ('WEBSOCKET', int),
    ],
)

httpProtocolTypes = HttpProtocolTypes(1, 2, 3)
