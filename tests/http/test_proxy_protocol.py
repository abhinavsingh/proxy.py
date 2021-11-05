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

from proxy.http.parser import PROXY_PROTOCOL_V2_SIGNATURE, ProxyProtocol


class TestProxyProtocol(unittest.TestCase):

    def setUp(self) -> None:
        self.protocol = ProxyProtocol()

    def test_v1(self) -> None:
        self.protocol.parse(b'PROXY TCP6 ::1 ::1 64665 8899')
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'TCP6')
        self.assertEqual(self.protocol.source, (b'::1', 64665))
        self.assertEqual(self.protocol.destination, (b'::1', 8899))

    def test_v1_example_from_spec(self) -> None:
        self.protocol.parse(b'PROXY TCP4 192.168.0.1 192.168.0.11 56324 443')
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'TCP4')
        self.assertEqual(self.protocol.source, (b'192.168.0.1', 56324))
        self.assertEqual(self.protocol.destination, (b'192.168.0.11', 443))

    def test_v1_worst_case_ipv4_from_spec(self) -> None:
        self.protocol.parse(
            b'PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535',
        )
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'TCP4')
        self.assertEqual(self.protocol.source, (b'255.255.255.255', 65535))
        self.assertEqual(
            self.protocol.destination,
            (b'255.255.255.255', 65535),
        )

    def test_v1_worst_case_ipv6_from_spec(self) -> None:
        self.protocol.parse(
            b'PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535',
        )
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'TCP6')
        self.assertEqual(self.protocol.source, (b'ffff:f...f:ffff', 65535))
        self.assertEqual(
            self.protocol.destination,
            (b'ffff:f...f:ffff', 65535),
        )

    def test_v1_worst_case_unknown_from_spec(self) -> None:
        self.protocol.parse(
            b'PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535',
        )
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'UNKNOWN')
        self.assertEqual(self.protocol.source, (b'ffff:f...f:ffff', 65535))
        self.assertEqual(
            self.protocol.destination,
            (b'ffff:f...f:ffff', 65535),
        )

    def test_v1_unknown_with_no_src_dst(self) -> None:
        self.protocol.parse(b'PROXY UNKNOWN')
        self.assertEqual(self.protocol.version, 1)
        self.assertEqual(self.protocol.family, b'UNKNOWN')
        self.assertEqual(self.protocol.source, None)
        self.assertEqual(self.protocol.destination, None)

    def test_v2_not_implemented(self) -> None:
        with self.assertRaises(NotImplementedError):
            self.protocol.parse(PROXY_PROTOCOL_V2_SIGNATURE)
            self.assertEqual(self.protocol.version, 2)

    def test_unknown_value_error(self) -> None:
        with self.assertRaises(ValueError):
            self.protocol.parse(PROXY_PROTOCOL_V2_SIGNATURE[:10])
            self.assertEqual(self.protocol.version, None)
