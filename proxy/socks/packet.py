# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import struct

from typing import Optional


class Socks4Packet:

    def __init__(self) -> None:
        # 1 byte, must be equal to 4
        self.vn: Optional[int] = None
        # 1 byte
        self.cd: Optional[int] = None
        # 2 bytes
        self.dstport: Optional[int] = None
        # 4 bytes
        self.dstip: Optional[bytes] = None
        # Variable bytes, NULL terminated
        self.userid: Optional[bytes] = None

    def parse(self, raw: memoryview) -> None:
        cursor = 0
        if self.vn is None:
            assert int(raw[cursor]) == 4
            self.vn = 4

    def pack(self) -> bytes:
        return struct.pack(
            '!bbHLs',
            self.vn, self.cd,
            self.dstport, self.dstip,
            self.userid or b''
        )
