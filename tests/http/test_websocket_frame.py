# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
import unittest

from proxy.http.websocket import WebsocketFrame, websocketOpcodes


class TestWebsocketFrame(unittest.TestCase):

    def test_build_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = WebsocketFrame()
        frame.fin = True
        frame.opcode = websocketOpcodes.TEXT_FRAME
        frame.masked = True
        frame.mask = b'\xc6\ti\x8d'
        frame.data = b'hello'
        self.assertEqual(frame.build(), raw)

    def test_parse_with_mask(self) -> None:
        raw = b'\x81\x85\xc6\ti\x8d\xael\x05\xe1\xa9'
        frame = WebsocketFrame()
        frame.parse(raw)
        self.assertEqual(frame.fin, True)
        self.assertEqual(frame.rsv1, False)
        self.assertEqual(frame.rsv2, False)
        self.assertEqual(frame.rsv3, False)
        self.assertEqual(frame.opcode, 0x1)
        self.assertEqual(frame.masked, True)
        assert frame.mask is not None
        self.assertEqual(frame.mask, b'\xc6\ti\x8d')
        self.assertEqual(frame.payload_length, 5)
        self.assertEqual(frame.data, b'hello')
