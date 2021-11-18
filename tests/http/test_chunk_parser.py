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

from proxy.http.parser import chunkParserStates, ChunkParser


class TestChunkParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = ChunkParser()

    def test_chunk_parse_basic(self) -> None:
        self.parser.parse(
            b''.join([
                b'4\r\n',
                b'Wiki\r\n',
                b'5\r\n',
                b'pedia\r\n',
                b'E\r\n',
                b' in\r\n\r\nchunks.\r\n',
                b'0\r\n',
                b'\r\n',
            ]),
        )
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, chunkParserStates.COMPLETE)

    def test_chunk_parse_issue_27(self) -> None:
        """Case when data ends with the chunk size but without ending CRLF."""
        self.parser.parse(b'3')
        self.assertEqual(self.parser.chunk, b'3')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_SIZE,
        )
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 3)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_DATA,
        )
        self.parser.parse(b'abc')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_SIZE,
        )
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_SIZE,
        )
        self.parser.parse(b'4\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 4)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_DATA,
        )
        self.parser.parse(b'defg\r\n0')
        self.assertEqual(self.parser.chunk, b'0')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(
            self.parser.state,
            chunkParserStates.WAITING_FOR_SIZE,
        )
        self.parser.parse(b'\r\n\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, chunkParserStates.COMPLETE)

    def test_to_chunks(self) -> None:
        self.assertEqual(
            b'f\r\n{"key":"value"}\r\n0\r\n\r\n',
            ChunkParser.to_chunks(b'{"key":"value"}'),
        )
