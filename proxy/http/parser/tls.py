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

from typing import NamedTuple, Optional


logger = logging.getLogger(__name__)


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

    def set_value(major: int, minor: int) -> None:
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

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsClientHello:
    """TLS Client Hello"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsServerHello:
    """TLS Server Hello"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsCertificate:
    """TLS Certificate"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsServerKeyExchange:
    """TLS Server Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsCertificateRequest:
    """TLS Certificate Request"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsServerHelloDone:
    """TLS Server Hello Done"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsCertificateVerify:
    """TLS Certificate Vefiry"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsClientKeyExchange:
    """TLS Client Key Exchange"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsFinished:
    """TLS Finished"""

    def __init__(self) -> None:
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        self.data = raw

    def build(self) -> bytes:
        return self.data


class TlsHandshake:
    """TLS Handshake"""

    def __init__(self) -> None:
        self.handshake_type: int = tlsHandshakeType.OTHER
        self.length: int = 0
        self.hello_request: Optional[TlsHelloRequest] = None
        self.client_hellp: Optional[TlsClientHello] = None
        self.server_hello: Optional[TlsServerHello] = None
        self.certificate: Optional[TlsCertificate] = None
        self.server_key_exchange: Optional[TlsServerKeyExchange] = None
        self.certificate_request: Optional[TlsCertificateRequest] = None
        self.server_hello_done: Optional[TlsServerHelloDone] = None
        self.certificate_verify: Optional[TlsCertificateVerify] = None
        self.client_key_exchange: Optional[TlsClientKeyExchange] = None
        self.finished: Optional[TlsFinished] = None
        self.data: Optional[bytes] = None

    def parse(self, raw: bytes) -> bytes:
        length = len(raw)
        if length < 4:
            logger.debug('invalid data, len(raw) = %s', legth)
            return raw
        else:
            payload_length, = struct.unpack('!H', b'\x00' + raw[1:4])
            self.length = payload_length
            if length < 4 + payload_length:
                logger.debug('incomplete data, len(raw) = %s, len(payload) = %s', length, payload_length)
                return raw
            else:
                # parse
                self.handshake_type = raw[0]
                self.data = raw[: 4 + payload_length]
                payload = raw[4: 4 + payload_length]
                if self.handshake_type == tlsHandshakeType.HELLO_REQUEST:
                    # parse hello request
                    self.hello_request = TlsHelloRequest()
                    self.hello_request.parse(payload)
                elif self.handshake_type == tlsHandshakeType.CLIENT_HELLO:
                    # parse client hello
                    self.client_hellp = TlsClientHello()
                    self.client_hellp.parse(payload)
                elif self.handshake_type == tlsHandshakeType.SERVER_HELLO:
                    # parse server hello
                    self.server_hello = TlsServerHello()
                    self.server_hello.parse(payload)
                elif self.handshake_type == tlsHandshakeType.CERTIFICATE:
                    # parse certficate
                    self.certificate = TlsCertificate()
                    self.certificate.parse(payload)
                elif self.handshake_type == tlsHandshakeType.SERVER_KEY_EXCHANGE:
                    # parse server key exchange
                    self.server_key_exchange = TlsServerKeyExchange()
                    self.server_key_exchange.parse(payload)
                elif self.handshake_type == tlsHandshakeType.CERTIFICATE_REQUEST:
                    # parse certificate request
                    self.certificate_request = TlsCertificateRequest()
                    self.certificate_request.parse(payload)
                elif self.handshake_type == tlsHandshakeType.SERVER_HELLO_DONE:
                    # parse server hello done
                    self.server_hello_done = TlsServerHelloDone()
                    self.server_hello_done.parse(payload)
                elif self.handshake_type == tlsHandshakeType.CERTIFICATE_VERIFY:
                    # parse certificate verify
                    self.certificate_verify = TlsCertificateVerify()
                    self.certificate_verify.parse(payload)
                elif self.handshake_type == tlsHandshakeType.CLIENT_KEY_EXCHANGE:
                    # parse client key exchange
                    self.client_key_exchange = TlsClientKeyExchange()
                    self.client_key_exchange.parse(payload)
                elif self.handshake_type == tlsHandshakeType.FINISHED:
                    # parse finished
                    self.finished = TlsFinished()
                    self.finished.parse(payload)
                return raw[4 + payload_length:]

    def build(self) -> bytes:
        return self.data


class TlsParser:
    """TLS packet parser"""

    def __init__(self) -> None:
        self.content_type: int = tlsContentType.OTHER
        self.protocol_version: Optional[TlsProtocolVersion] = None
        self.length: int = 0
        self.data: Optional[bytes] = None
        # only parse hand shake payload temporary
        self.handshake: Optional[TlsHandshake] = None

    def parse(self, raw: bytes) -> bytes:
        """parse TLS fragmentation
        Ref: https://datatracker.ietf.org/doc/html/rfc5246#page-15
        """
        length = len(raw)
        if length < 5:
            logger.debug('invalid data, len(raw) = %s', length)
            return raw
        else:
            payload_length, = struct.unpack('!H', raw[3:5])
            self.length = payload_length
            if length < 5 + payload_length:
                logger.debug('incomplete data, len(raw) = %s, len(payload) = %s', length, payload_length)
                return raw
            else:
                # parse
                self.content_type = raw[0]
                self.data = raw[: 5 + payload_length]
                payload = raw[5:5 + payload_length]
                if self.content_type == tlsContentType.HANDSHAKE:
                    # parse handshake
                    self.handshake = TlsHandshake()
                    self.handshake.parse(payload)
                    self.data = raw[:5 + payload_length]
                return raw[5 + payload_length:]

    def build(self) -> bytes:
        return self.data


