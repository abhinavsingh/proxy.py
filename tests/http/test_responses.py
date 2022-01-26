# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       nd
"""
import gzip

import unittest

from proxy.http.parser import ChunkParser
from proxy.http.responses import okResponse
from proxy.common.constants import CRLF


class TestResponses(unittest.TestCase):

    def test_basic(self) -> None:
        self.assertEqual(
            okResponse(),
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n',
        )
        self.assertEqual(
            okResponse(
                headers={
                    b'X-Custom-Header': b'my value',
                },
            ),
            b'HTTP/1.1 200 OK\r\nX-Custom-Header: my value\r\nContent-Length: 0\r\n\r\n',
        )
        self.assertEqual(
            okResponse(
                content=b'Hello World',
                headers={
                    b'X-Custom-Header': b'my value',
                },
            ),
            b'HTTP/1.1 200 OK\r\nX-Custom-Header: my value\r\nContent-Length: 11\r\n\r\nHello World',
        )

    def test_compression(self) -> None:
        content = b'H' * 21
        self.assertEqual(
            gzip.decompress(
                okResponse(
                    content=content,
                    headers={
                        b'X-Custom-Header': b'my value',
                    },
                ).tobytes().split(CRLF + CRLF, maxsplit=1)[-1],
            ),
            content,
        )
        self.assertEqual(
            okResponse(
                content=content,
                headers={
                    b'Host': b'jaxl.com',
                },
                min_compression_length=len(content),
            ),
            b'HTTP/1.1 200 OK\r\nHost: jaxl.com\r\nContent-Length: 21\r\n\r\nHHHHHHHHHHHHHHHHHHHHH',
        )

    def test_close_header(self) -> None:
        self.assertEqual(
            okResponse(
                content=b'Hello World',
                headers={
                    b'Host': b'jaxl.com',
                },
                conn_close=True,
            ),
            b'HTTP/1.1 200 OK\r\nHost: jaxl.com\r\nContent-Length: 11\r\nConnection: close\r\n\r\nHello World'
        )

    def test_chunked_without_compression(self) -> None:
        chunks = ChunkParser.to_chunks(b'Hello World', chunk_size=5)
        self.assertEqual(
            okResponse(
                content=chunks,
                headers={
                    b'Transfer-Encoding': b'chunked',
                },
                # Avoid compressing chunks for demo purposes here
                # Ideally you should omit this flag and send
                # compressed chunks.
                min_compression_length=len(chunks),
            ),
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n5\r\n Worl\r\n1\r\nd\r\n0\r\n\r\n',
        )

    def test_chunked_with_compression(self) -> None:
        chunks = ChunkParser.to_chunks(b'Hello World', chunk_size=5)
        self.assertEqual(
            gzip.decompress(
                okResponse(
                    content=chunks,
                    headers={
                        b'Transfer-Encoding': b'chunked',
                    },
                ).tobytes().split(CRLF + CRLF, maxsplit=1)[-1],
            ),
            chunks,
        )
