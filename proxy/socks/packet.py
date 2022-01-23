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


NULL = b'\x00'


class Socks4Packet:
    """SOCKS4 and SOCKS4a protocol parser.

    FIXME: Currently doesn't buffer during parsing and expects
    packet to arrive within a single socket receive event.
    """

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
        # Parse vn
        if self.vn is None:
            assert int(raw[cursor]) == 4
            self.vn = 4
        cursor += 1
        # Parse cd
        self.cd = raw[cursor]
        cursor += 1
        # Parse dstport
        self.dstport = struct.unpack('!H', raw[cursor:cursor+2])[0]
        cursor += 2
        # Parse dstip
        self.dstip = struct.unpack('!4s', raw[cursor:cursor+4])[0]
        cursor += 4
        # Parse userid
        ulen = len(raw) - cursor - 1
        self.userid = struct.unpack(
            '!%ds' % ulen, raw[cursor:cursor+ulen],
        )[0]
        cursor += ulen
        # Assert null terminated
        assert raw[cursor] == NULL[0]

    def pack(self) -> bytes:
        user_id = self.userid or b''
        return struct.pack(
            '!bbH4s%ds' % len(user_id),
            self.vn, self.cd,
            self.dstport, self.dstip,
            user_id,
        ) + NULL
