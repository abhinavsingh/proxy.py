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

from .types import tlsHandshakeType
from .hello import TlsHelloRequest, TlsClientHello, TlsServerHello, TlsServerHelloDone
from .certificate import TlsCertificate, TlsCertificateRequest, TlsCertificateVerify
from .key_exchange import TlsClientKeyExchange, TlsServerKeyExchange
from .finished import TlsFinished

logger = logging.getLogger(__name__)


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
