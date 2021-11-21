import socket
import unittest

from proxy.socks import Socks4Packet, socks4Operations


class TestSocks4Packet(unittest.TestCase):

    def test_pack(self) -> None:
        pkt = Socks4Packet()
        pkt.vn = 4
        pkt.cd = socks4Operations.CONNECT
        pkt.dstport = 80
        pkt.dstip = socket.inet_aton('66.102.7.99')
        pkt.userid = b'Fred'
        wiki = b'\x04\x01\x00PBf\x07cF'
        self.assertEqual(
            pkt.pack(),
            wiki,
        )

    def test_parse(self) -> None:
        wiki = memoryview(
            b'\x04\x01P\x00\x00\x00\x00\x00c\x07fB\x00\x00\x00\x00F')
        pkt = Socks4Packet()
        pkt.parse(wiki)
