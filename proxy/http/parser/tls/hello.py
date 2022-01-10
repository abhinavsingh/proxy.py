# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import struct
import logging

from typing import Optional, Tuple

from .pretty import pretty_hexlify

logger = logging.getLogger(__name__)


class TlsHelloRequest:
    """TLS Hello Request"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> None:
        self.data = raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsClientHello:
    """TLS Client Hello"""

    def __init__(self) -> None:
        self.protocol_version: Optional[bytes] = None
        self.random: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.cipher_suite: Optional[bytes] = None
        self.compression_method: Optional[bytes] = None
        self.extension: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        try:
            idx = 0
            length = len(raw)
            self.protocol_version = raw[idx:idx + 2]
            idx += 2
            self.random = raw[idx:idx + 32]
            idx += 32
            session_length = raw[idx]
            self.session_id = raw[idx: idx + 1 + session_length]
            idx += 1 + session_length
            cipher_suite_length, = struct.unpack('!H', raw[idx: idx + 2])
            self.cipher_suite = raw[idx: idx + 2 + cipher_suite_length]
            idx += 2 + cipher_suite_length
            compression_method_length = raw[idx]
            self.compression_method = raw[
                idx: idx +
                1 + compression_method_length
            ]
            idx += 1 + compression_method_length
            # extension
            if idx == length:
                self.extension = b''
            else:
                extension_length, = struct.unpack('!H', raw[idx: idx + 2])
                self.extension = raw[idx: idx + 2 + extension_length]
                idx += 2 + extension_length
            return True, raw[idx:]
        except Exception as e:
            logger.exception(e)
            return False, raw

    def build(self) -> bytes:
        # calculate length
        return b''.join([
            bs for bs in (
                self.protocol_version, self.random, self.session_id, self.cipher_suite,
                self.compression_method, self.extension,
            ) if bs is not None
        ])

    def format(self) -> str:
        parts = []
        parts.append(
            'Protocol Version: %s' % (
                pretty_hexlify(self.protocol_version)
                if self.protocol_version is not None
                else ''
            ),
        )
        parts.append(
            'Random: %s' % (
                pretty_hexlify(self.random)
                if self.random is not None else ''
            ),
        )
        parts.append(
            'Session ID: %s' % (
                pretty_hexlify(self.session_id)
                if self.session_id is not None
                else ''
            ),
        )
        parts.append(
            'Cipher Suite: %s' % (
                pretty_hexlify(self.cipher_suite)
                if self.cipher_suite is not None
                else ''
            ),
        )
        parts.append(
            'Compression Method: %s' % (
                pretty_hexlify(self.compression_method)
                if self.compression_method is not None
                else ''
            ),
        )
        parts.append(
            'Extension: %s' % (
                pretty_hexlify(self.extension)
                if self.extension is not None
                else ''
            ),
        )
        return os.linesep.join(parts)


class TlsServerHello:
    """TLS Server Hello"""

    def __init__(self) -> None:
        self.protocol_version: Optional[bytes] = None
        self.random: Optional[bytes] = None
        self.session_id: Optional[bytes] = None
        self.cipher_suite: Optional[bytes] = None
        self.compression_method: Optional[bytes] = None
        self.extension: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        try:
            idx = 0
            length = len(raw)
            self.protocol_version = raw[idx:idx + 2]
            idx += 2
            self.random = raw[idx:idx + 32]
            idx += 32
            session_length = raw[idx]
            self.session_id = raw[idx: idx + 1 + session_length]
            idx += 1 + session_length
            self.cipher_suite = raw[idx: idx + 2]
            idx += 2
            compression_method_length = raw[idx]
            self.compression_method = raw[
                idx: idx +
                1 + compression_method_length
            ]
            idx += 1 + compression_method_length
            # extension
            if idx == length:
                self.extension = b''
            else:
                extension_length, = struct.unpack('!H', raw[idx: idx + 2])
                self.extension = raw[idx: idx + 2 + extension_length]
                idx += 2 + extension_length
            return True, raw[idx:]
        except Exception as e:
            logger.exception(e)
            return False, raw

    def build(self) -> bytes:
        return b''.join([
            bs for bs in (
                self.protocol_version, self.random, self.session_id, self.cipher_suite,
                self.compression_method, self.extension,
            ) if bs is not None
        ])

    def format(self) -> str:
        parts = []
        parts.append(
            'Protocol Version: %s' % (
                pretty_hexlify(self.protocol_version)
                if self.protocol_version is not None
                else ''
            ),
        )
        parts.append(
            'Random: %s' % (
                pretty_hexlify(self.random)
                if self.random is not None
                else ''
            ),
        )
        parts.append(
            'Session ID: %s' % (
                pretty_hexlify(self.session_id)
                if self.session_id is not None
                else ''
            ),
        )
        parts.append(
            'Cipher Suite: %s' % (
                pretty_hexlify(self.cipher_suite)
                if self.cipher_suite is not None
                else ''
            ),
        )
        parts.append(
            'Compression Method: %s' % (
                pretty_hexlify(self.compression_method)
                if self.compression_method is not None
                else ''
            ),
        )
        parts.append(
            'Extension: %s' % (
                pretty_hexlify(self.extension)
                if self.extension is not None
                else ''
            ),
        )
        return os.linesep.join(parts)


class TlsServerHelloDone:
    """TLS Server Hello Done"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data
