# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import binascii


def pretty_hexlify(raw: bytes) -> str:
    hexlified = binascii.hexlify(raw).decode('utf-8')
    return ' '.join([hexlified[i: i+2] for i in range(0, len(hexlified), 2)])
