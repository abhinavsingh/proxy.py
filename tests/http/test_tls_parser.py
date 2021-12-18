# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import binascii
import re
import os

from proxy.http.parser.tls import TlsParser
from proxy.http.parser.tls import tlsContentType, tlsHandshakeType


class TestTlsParser(unittest.TestCase):
    """Ref: https://tls.ulfheim.net/"""

    def unhexlify(self, raw: str) -> bytes:
        return binascii.unhexlify(re.sub(r'\s', '', raw))

    def test_parse_client_hello(self) -> None:
        data = """
                16 03 01 00 a5 01 00 00 a1 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14
                15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 00 20 cc a8 cc a9 c0 2f c0 30 c0 2b c0 2c c0 13 c0 09 c0 14
                c0 0a 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 01 00 00 58 00 00 00 18 00 16 00 00 13 65 78 61 6d 70
                6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00
                17 00 18 00 19 00 0b 00 02 01 00 00 0d 00 12 00 10 04 01 04 03 05 01 05 03 06 01 06 03 02 01 02
                03 ff 01 00 01 00 00 12 00 00
                """
        tls = TlsParser()
        tls.parse(self.unhexlify(data))
        self.assertEqual(tls.content_type, tlsContentType.HANDSHAKE)
        self.assertEqual(tls.length, b'\x00\xa5')
        assert tls.handshake
        self.assertEqual(tls.handshake.msg_type, tlsHandshakeType.CLIENT_HELLO)
        self.assertEqual(tls.handshake.length, b'\x00\x00\xa1')
        self.assertEqual(len(tls.handshake.build()), 0xA1 + 0x04)
        assert tls.handshake.client_hello
        self.assertEqual(
            tls.handshake.client_hello.protocol_version, b'\x03\x03',
        )
        self.assertEqual(
            tls.handshake.client_hello.random, self.unhexlify(
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f',
            ),
        )

    def test_parse_server_hello(self) -> None:
        data = open(
            os.path.join(
                os.path.dirname(__file__),
                'tls_server_hello.data',
            ), 'r',
        ).read()
        tls = TlsParser()
        tls.parse(self.unhexlify(data))
        self.assertEqual(tls.content_type, tlsContentType.HANDSHAKE)
        assert tls.handshake
        self.assertEqual(tls.handshake.msg_type, tlsHandshakeType.SERVER_HELLO)
        assert tls.handshake.server_hello
        self.assertEqual(
            tls.handshake.server_hello.protocol_version, b'\x03\x03',
        )
        print(tls.handshake.server_hello.format())
