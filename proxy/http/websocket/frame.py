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
       websocket
       Websocket
"""
import io
import base64
import struct
import hashlib
import secrets
import logging

from typing import TypeVar, Type, Optional, NamedTuple


WebsocketOpcodes = NamedTuple(
    'WebsocketOpcodes', [
        ('CONTINUATION_FRAME', int),
        ('TEXT_FRAME', int),
        ('BINARY_FRAME', int),
        ('CONNECTION_CLOSE', int),
        ('PING', int),
        ('PONG', int),
    ],
)
websocketOpcodes = WebsocketOpcodes(0x0, 0x1, 0x2, 0x8, 0x9, 0xA)


V = TypeVar('V', bound='WebsocketFrame')

logger = logging.getLogger(__name__)


class WebsocketFrame:
    """Websocket frames parser and constructor."""

    GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    def __init__(self) -> None:
        self.fin: bool = False
        self.rsv1: bool = False
        self.rsv2: bool = False
        self.rsv3: bool = False
        self.opcode: int = 0
        self.masked: bool = False
        self.payload_length: Optional[int] = None
        self.mask: Optional[bytes] = None
        self.data: Optional[bytes] = None

    @classmethod
    def text(cls: Type[V], data: bytes) -> bytes:
        frame = cls()
        frame.fin = True
        frame.opcode = websocketOpcodes.TEXT_FRAME
        frame.data = data
        return frame.build()

    def reset(self) -> None:
        self.fin = False
        self.rsv1 = False
        self.rsv2 = False
        self.rsv3 = False
        self.opcode = 0
        self.masked = False
        self.payload_length = None
        self.mask = None
        self.data = None

    def parse(self, raw: bytes) -> bytes:
        cur = 0
        self._parse_fin_and_rsv(raw[cur])
        cur += 1

        self._parse_mask_and_payload(raw[cur])
        cur += 1

        if self.payload_length == 126:
            data = raw[cur: cur + 2]
            self.payload_length, = struct.unpack('!H', data)
            cur += 2
        elif self.payload_length == 127:
            data = raw[cur: cur + 8]
            self.payload_length, = struct.unpack('!Q', data)
            cur += 8

        if self.masked:
            self.mask = raw[cur: cur + 4]
            cur += 4

        if self.payload_length and self.payload_length > 0:
            self.data = raw[cur: cur + self.payload_length]
            cur += self.payload_length
            if self.masked:
                assert self.mask is not None
                self.data = self.apply_mask(self.data, self.mask)

        return raw[cur:]

    def build(self) -> bytes:
        """Payload length:  7 bits, 7+16 bits, or 7+64 bits

        The length of the "Payload data", in bytes: if 0-125, that is the
        payload length.  If 126, the following 2 bytes interpreted as a
        16-bit unsigned integer are the payload length.  If 127, the
        following 8 bytes interpreted as a 64-bit unsigned integer (the
        most significant bit MUST be 0) are the payload length.  Multibyte
        length quantities are expressed in network byte order.  Note that
        in all cases, the minimal number of bytes MUST be used to encode
        the length, for example, the length of a 124-byte-long string
        can't be encoded as the sequence 126, 0, 124.  The payload length
        is the length of the "Extension data" + the length of the
        "Application data".  The length of the "Extension data" may be
        zero, in which case the payload length is the length of the
        "Application data".

        Ref https://datatracker.ietf.org/doc/html/rfc6455
        """
        if self.payload_length is None and self.data:
            self.payload_length = len(self.data)
        raw = io.BytesIO()
        raw.write(
            struct.pack(
                '!B',
                (1 << 7 if self.fin else 0) |
                (1 << 6 if self.rsv1 else 0) |
                (1 << 5 if self.rsv2 else 0) |
                (1 << 4 if self.rsv3 else 0) |
                self.opcode,
            ),
        )
        assert self.payload_length is not None
        if self.payload_length < 126:
            raw.write(
                struct.pack(
                    '!B',
                    (1 << 7 if self.masked else 0) | self.payload_length,
                ),
            )
        elif self.payload_length < 1 << 16:
            raw.write(
                struct.pack(
                    '!BH',
                    (1 << 7 if self.masked else 0) | 126,
                    self.payload_length,
                ),
            )
        elif self.payload_length < 1 << 64:
            raw.write(
                struct.pack(
                    '!BQ',
                    (1 << 7 if self.masked else 0) | 127,
                    self.payload_length,
                ),
            )
        else:
            raise ValueError(
                f'Invalid payload_length { self.payload_length },'
                f'maximum allowed { 1 << 64 }',
            )
        if self.masked and self.data:
            mask = secrets.token_bytes(4) if self.mask is None else self.mask
            raw.write(mask)
            raw.write(self.apply_mask(self.data, mask))
        elif self.data:
            raw.write(self.data)
        return raw.getvalue()

    def _parse_fin_and_rsv(self, byte: int) -> None:
        self.fin = bool(byte & 1 << 7)
        self.rsv1 = bool(byte & 1 << 6)
        self.rsv2 = bool(byte & 1 << 5)
        self.rsv3 = bool(byte & 1 << 4)
        self.opcode = byte & 0b00001111

    def _parse_mask_and_payload(self, byte: int) -> None:
        self.masked = bool(byte & 0b10000000)
        self.payload_length = byte & 0b01111111

    @staticmethod
    def apply_mask(data: bytes, mask: bytes) -> bytes:
        raw = bytearray(data)
        for i in range(len(raw)):
            raw[i] = raw[i] ^ mask[i % 4]
        return bytes(raw)

    @staticmethod
    def key_to_accept(key: bytes) -> bytes:
        sha1 = hashlib.sha1()
        sha1.update(key + WebsocketFrame.GUID)
        return base64.b64encode(sha1.digest())
