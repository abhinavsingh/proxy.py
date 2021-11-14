# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional, Tuple
from ...common.constants import WHITESPACE

PROXY_PROTOCOL_V2_SIGNATURE = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'


class ProxyProtocol:
    """Reference https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt"""

    def __init__(self) -> None:
        self.version: Optional[int] = None
        self.family: Optional[bytes] = None
        self.source: Optional[Tuple[bytes, int]] = None
        self.destination: Optional[Tuple[bytes, int]] = None

    def parse(self, raw: bytes) -> None:
        if raw.startswith(b'PROXY'):
            self.version = 1
            # Per spec, v1 line cannot exceed this limit
            assert len(raw) <= 57
            line = raw.split(WHITESPACE)
            assert line[0] == b'PROXY' and line[1] in (
                b'TCP4', b'TCP6', b'UNKNOWN',
            )
            self.family = line[1]
            if len(line) == 6:
                self.source = (line[2], int(line[4]))
                self.destination = (line[3], int(line[5]))
            else:
                assert self.family == b'UNKNOWN'
        elif raw.startswith(PROXY_PROTOCOL_V2_SIGNATURE):
            self.version = 2
            raise NotImplementedError()
        else:
            raise ValueError('Neither a v1 or v2 proxy protocol packet')
