# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import NamedTuple


Socks4Operations = NamedTuple(
    'Socks4Operations', [
        ('CONNECT', int),
        ('BIND', int),
    ],
)

socks4Operations = Socks4Operations(1, 2)
