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
import logging

from typing import Optional, Tuple

from .types import tlsContentType
from .certificate import TlsCertificate
from .handshake import TlsHandshake

logger = logging.getLogger(__name__)


class TlsParser:
    """TLS packet parser"""

    def __init__(self) -> None:
        self.content_type: int = tlsContentType.OTHER
        self.protocol_version: Optional[bytes] = None
        self.length: Optional[bytes] = None
        # only parse hand shake payload temporary
        self.handshake: Optional[TlsHandshake] = None
        self.certificate: Optional[TlsCertificate]

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        """Parse TLS fragmentation.

        References:

        https://datatracker.ietf.org/doc/html/rfc5246#page-15
        https://datatracker.ietf.org/doc/html/rfc5077#page-3
        https://datatracker.ietf.org/doc/html/rfc8446#page-10
        """
        length = len(raw)
        if length < 5:
            logger.debug('invalid data, len(raw) = %s', length)
            return False, raw
        payload_length, = struct.unpack('!H', raw[3:5])
        self.protocol_version
        if length < 5 + payload_length:
            logger.debug(
                'incomplete data, len(raw) = %s, len(payload) = %s', length, payload_length,
            )
            return False, raw
        # parse
        self.content_type = raw[0]
        self.protocol_version = raw[1:3]
        self.length = raw[3:5]
        payload = raw[5:5 + payload_length]
        if self.content_type == tlsContentType.HANDSHAKE:
            # parse handshake
            self.handshake = TlsHandshake()
            self.handshake.parse(payload)
        return True, raw[5 + payload_length:]

    def build(self) -> bytes:
        data = b''
        data += bytes([self.content_type])
        assert self.protocol_version
        data += self.protocol_version
        payload = b''
        if self.content_type == tlsContentType.HANDSHAKE:
            assert self.handshake
            payload += self.handshake.build()
        length = struct.pack('!H', len(payload))
        data += length
        data += payload
        return data
