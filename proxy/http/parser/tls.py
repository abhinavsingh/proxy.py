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
import binascii
import struct
import logging

from typing import NamedTuple, Optional, Tuple


logger = logging.getLogger(__name__)


def pretty_hexlify(raw: bytes) -> str:
    hexlified = binascii.hexlify(raw).decode('utf-8')
    return ' '.join([hexlified[i: i+2] for i in range(0, len(hexlified), 2)])


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


class TlsProtocolVersion:
    """Protocol Version"""

    def __init__(self) -> None:
        self.major = 0
        self.minor = 0

    def set_value(self, major: int, minor: int) -> None:
        self.major = major
        self.minor = minor


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


class TlsCertificate:
    """TLS Certificate"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        self.data = raw
        return True, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsServerKeyExchange:
    """TLS Server Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        self.data = raw
        return True, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsCertificateRequest:
    """TLS Certificate Request"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsServerHelloDone:
    """TLS Server Hello Done"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsCertificateVerify:
    """TLS Certificate Verify"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsClientKeyExchange:
    """TLS Client Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsFinished:
    """TLS Finished"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        return False, raw

    def build(self) -> bytes:
        assert self.data
        return self.data


class TlsHandshake:
    """TLS Handshake"""

    def __init__(self) -> None:
        self.msg_type: int = tlsHandshakeType.OTHER
        self.length: Optional[bytes] = None
        self.hello_request: Optional[TlsHelloRequest] = None
        self.client_hello: Optional[TlsClientHello] = None
        self.server_hello: Optional[TlsServerHello] = None
        self.certificate: Optional[TlsCertificate] = None
        self.server_key_exchange: Optional[TlsServerKeyExchange] = None
        self.certificate_request: Optional[TlsCertificateRequest] = None
        self.server_hello_done: Optional[TlsServerHelloDone] = None
        self.certificate_verify: Optional[TlsCertificateVerify] = None
        self.client_key_exchange: Optional[TlsClientKeyExchange] = None
        self.finished: Optional[TlsFinished] = None
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        length = len(raw)
        if length < 4:
            logger.debug('invalid data, len(raw) = %s', length)
            return False, raw
        else:
            payload_length, = struct.unpack('!I', b'\x00' + raw[1:4])
            self.length = payload_length
            if length < 4 + payload_length:
                logger.debug(
                    'incomplete data, len(raw) = %s, len(payload) = %s', length, payload_length,
                )
                return False, raw
            # parse
            self.msg_type = raw[0]
            self.length = raw[1:4]
            self.data = raw[: 4 + payload_length]
            payload = raw[4: 4 + payload_length]
            if self.msg_type == tlsHandshakeType.HELLO_REQUEST:
                # parse hello request
                self.hello_request = TlsHelloRequest()
                self.hello_request.parse(payload)
            elif self.msg_type == tlsHandshakeType.CLIENT_HELLO:
                # parse client hello
                self.client_hello = TlsClientHello()
                self.client_hello.parse(payload)
            elif self.msg_type == tlsHandshakeType.SERVER_HELLO:
                # parse server hello
                self.server_hello = TlsServerHello()
                self.server_hello.parse(payload)
            elif self.msg_type == tlsHandshakeType.CERTIFICATE:
                # parse certificate
                self.certificate = TlsCertificate()
                self.certificate.parse(payload)
            elif self.msg_type == tlsHandshakeType.SERVER_KEY_EXCHANGE:
                # parse server key exchange
                self.server_key_exchange = TlsServerKeyExchange()
                self.server_key_exchange.parse(payload)
            elif self.msg_type == tlsHandshakeType.CERTIFICATE_REQUEST:
                # parse certificate request
                self.certificate_request = TlsCertificateRequest()
                self.certificate_request.parse(payload)
            elif self.msg_type == tlsHandshakeType.SERVER_HELLO_DONE:
                # parse server hello done
                self.server_hello_done = TlsServerHelloDone()
                self.server_hello_done.parse(payload)
            elif self.msg_type == tlsHandshakeType.CERTIFICATE_VERIFY:
                # parse certificate verify
                self.certificate_verify = TlsCertificateVerify()
                self.certificate_verify.parse(payload)
            elif self.msg_type == tlsHandshakeType.CLIENT_KEY_EXCHANGE:
                # parse client key exchange
                self.client_key_exchange = TlsClientKeyExchange()
                self.client_key_exchange.parse(payload)
            elif self.msg_type == tlsHandshakeType.FINISHED:
                # parse finished
                self.finished = TlsFinished()
                self.finished.parse(payload)
            return True, raw[4 + payload_length:]

    def build(self) -> bytes:
        data = b''
        data += bytes([self.msg_type])
        payload = b''
        if self.msg_type == tlsHandshakeType.CLIENT_HELLO:
            assert self.client_hello
            payload = self.client_hello.build()
        elif self.msg_type == tlsHandshakeType.SERVER_HELLO:
            assert self.server_hello
            payload = self.server_hello.build()
        elif self.msg_type == tlsHandshakeType.CERTIFICATE:
            assert self.certificate
            payload = self.certificate.build()
        elif self.msg_type == tlsHandshakeType.SERVER_KEY_EXCHANGE:
            assert self.server_key_exchange
            payload = self.server_key_exchange.build()
        # calculate length
        length = struct.pack('!I', len(payload))[1:]
        data += length
        data += payload
        return data


class TlsParser:
    """TLS packet parser"""

    def __init__(self) -> None:
        self.content_type: int = tlsContentType.OTHER
        self.protocol_version: Optional[TlsProtocolVersion] = None
        self.length: Optional[bytes] = None
        # only parse hand shake payload temporary
        self.handshake: Optional[TlsHandshake] = None
        self.certificate: Optional[TlsCertificate]

    def parse(self, raw: bytes) -> Tuple[bool, bytes]:
        """parse TLS fragmentation
        Ref: https://datatracker.ietf.org/doc/html/rfc5246#page-15
             https://datatracker.ietf.org/doc/html/rfc5077#page-3
             https://datatracker.ietf.org/doc/html/rfc8446#page-10
        """
        length = len(raw)
        if length < 5:
            logger.debug('invalid data, len(raw) = %s', length)
            return False, raw
        else:
            payload_length, = struct.unpack('!H', raw[3:5])
            self.protocol_version
            if length < 5 + payload_length:
                logger.debug(
                    'incomplete data, len(raw) = %s, len(payload) = %s', length, payload_length,
                )
                return False, raw
            else:
                # parse
                self.content_type = raw[0]
                # ???
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
        # ???
        data += self.protocol_version
        payload = b''
        if self.content_type == tlsContentType.HANDSHAKE:
            assert self.handshake
            payload += self.handshake.build()
        length = struct.pack('!H', len(payload))
        data += length
        data += payload
        return data
