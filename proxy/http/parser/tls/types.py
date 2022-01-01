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

TlsContentType = NamedTuple(
    'TlsContentType', [
        ('CHANGE_CIPHER_SPEC', int),
        ('ALERT', int),
        ('HANDSHAKE', int),
        ('APPLICATION_DATA', int),
        ('OTHER', int),
    ],
)
tlsContentType = TlsContentType(20, 21, 22, 23, 255)


TlsHandshakeType = NamedTuple(
    'TlsHandshakeType', [
        ('HELLO_REQUEST', int),
        ('CLIENT_HELLO', int),
        ('SERVER_HELLO', int),
        ('CERTIFICATE', int),
        ('SERVER_KEY_EXCHANGE', int),
        ('CERTIFICATE_REQUEST', int),
        ('SERVER_HELLO_DONE', int),
        ('CERTIFICATE_VERIFY', int),
        ('CLIENT_KEY_EXCHANGE', int),
        ('FINISHED', int),
        ('OTHER', int),
    ],
)
tlsHandshakeType = TlsHandshakeType(0, 1, 2, 11, 12, 13, 14, 15, 16, 20, 255)
