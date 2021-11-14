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


TcpConnectionTypes = NamedTuple(
    'TcpConnectionTypes', [
        ('SERVER', int),
        ('CLIENT', int),
    ],
)
tcpConnectionTypes = TcpConnectionTypes(1, 2)
