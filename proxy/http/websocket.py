# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import hashlib
import base64
import selectors
import struct
import socket
import secrets
import ssl
import ipaddress
import logging
import io

from typing import TypeVar, Type, Optional, NamedTuple, Union, Callable

from .parser import httpParserTypes, HttpParser

from ..common.constants import DEFAULT_BUFFER_SIZE
from ..common.utils import new_socket_connection, build_websocket_handshake_request
from ..core.connection import tcpConnectionTypes, TcpConnection


WebsocketOpcodes = NamedTuple('WebsocketOpcodes', [
    ('CONTINUATION_FRAME', int),
    ('TEXT_FRAME', int),
    ('BINARY_FRAME', int),
    ('CONNECTION_CLOSE', int),
    ('PING', int),
    ('PONG', int),
])
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

    def parse_fin_and_rsv(self, byte: int) -> None:
        self.fin = bool(byte & 1 << 7)
        self.rsv1 = bool(byte & 1 << 6)
        self.rsv2 = bool(byte & 1 << 5)
        self.rsv3 = bool(byte & 1 << 4)
        self.opcode = byte & 0b00001111

    def parse_mask_and_payload(self, byte: int) -> None:
        self.masked = bool(byte & 0b10000000)
        self.payload_length = byte & 0b01111111

    def build(self) -> bytes:
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
                self.opcode
            ))
        assert self.payload_length is not None
        if self.payload_length < 126:
            raw.write(
                struct.pack(
                    '!B',
                    (1 << 7 if self.masked else 0) | self.payload_length
                )
            )
        elif self.payload_length < 1 << 16:
            raw.write(
                struct.pack(
                    '!BH',
                    (1 << 7 if self.masked else 0) | 126,
                    self.payload_length
                )
            )
        elif self.payload_length < 1 << 64:
            raw.write(
                struct.pack(
                    '!BHQ',
                    (1 << 7 if self.masked else 0) | 127,
                    self.payload_length
                )
            )
        else:
            raise ValueError(f'Invalid payload_length { self.payload_length },'
                             f'maximum allowed { 1 << 64 }')
        if self.masked and self.data:
            mask = secrets.token_bytes(4) if self.mask is None else self.mask
            raw.write(mask)
            raw.write(self.apply_mask(self.data, mask))
        elif self.data:
            raw.write(self.data)
        return raw.getvalue()

    def parse(self, raw: bytes) -> bytes:
        cur = 0
        self.parse_fin_and_rsv(raw[cur])
        cur += 1

        self.parse_mask_and_payload(raw[cur])
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

        assert self.payload_length
        self.data = raw[cur: cur + self.payload_length]
        cur += self.payload_length
        if self.masked:
            assert self.mask is not None
            self.data = self.apply_mask(self.data, self.mask)

        return raw[cur:]

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


class WebsocketClient(TcpConnection):

    def __init__(self,
                 hostname: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                 port: int,
                 path: bytes = b'/',
                 on_message: Optional[Callable[[WebsocketFrame], None]] = None) -> None:
        super().__init__(tcpConnectionTypes.CLIENT)
        self.hostname: Union[ipaddress.IPv4Address,
                             ipaddress.IPv6Address] = hostname
        self.port: int = port
        self.path: bytes = path
        self.sock: socket.socket = new_socket_connection(
            (str(self.hostname), self.port))
        self.on_message: Optional[Callable[[
            WebsocketFrame], None]] = on_message
        self.upgrade()
        self.sock.setblocking(False)
        self.selector: selectors.DefaultSelector = selectors.DefaultSelector()

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        return self.sock

    def upgrade(self) -> None:
        key = base64.b64encode(secrets.token_bytes(16))
        self.sock.send(build_websocket_handshake_request(key, url=self.path))
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(self.sock.recv(DEFAULT_BUFFER_SIZE))
        accept = response.header(b'Sec-Websocket-Accept')
        assert WebsocketFrame.key_to_accept(key) == accept

    def ping(self, data: Optional[bytes] = None) -> None:
        pass

    def pong(self, data: Optional[bytes] = None) -> None:
        pass

    def shutdown(self, _data: Optional[bytes] = None) -> None:
        """Closes connection with the server."""
        super().close()

    def run_once(self) -> bool:
        ev = selectors.EVENT_READ
        if self.has_buffer():
            ev |= selectors.EVENT_WRITE
        self.selector.register(self.sock.fileno(), ev)
        events = self.selector.select(timeout=1)
        self.selector.unregister(self.sock)
        for key, mask in events:
            if mask & selectors.EVENT_READ and self.on_message:
                raw = self.recv()
                if raw is None or raw == b'':
                    self.closed = True
                    logger.debug('Websocket connection closed by server')
                    return True
                frame = WebsocketFrame()
                frame.parse(raw)
                self.on_message(frame)
            elif mask & selectors.EVENT_WRITE:
                logger.debug(self.buffer)
                self.flush()
        return False

    def run(self) -> None:
        logger.debug('running')
        try:
            while not self.closed:
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.selector.unregister(self.sock)
                self.sock.shutdown(socket.SHUT_WR)
            except Exception as e:
                logging.exception(
                    'Exception while shutdown of websocket client', exc_info=e)
            self.sock.close()
        logger.info('done')
