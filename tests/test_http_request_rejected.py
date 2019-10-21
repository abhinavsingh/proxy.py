# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest

from core.http_parser import HttpParser, httpParserTypes
from core.http_proxy import HttpRequestRejected
from core.constants import CRLF, PROXY_AGENT_HEADER


class TestHttpRequestRejected(unittest.TestCase):

    def setUp(self) -> None:
        self.request = HttpParser(httpParserTypes.REQUEST_PARSER)

    def test_empty_response(self) -> None:
        e = HttpRequestRejected()
        self.assertEqual(e.response(self.request), None)

    def test_status_code_response(self) -> None:
        e = HttpRequestRejected(status_code=200, reason=b'OK')
        self.assertEqual(e.response(self.request), CRLF.join([
            b'HTTP/1.1 200 OK',
            PROXY_AGENT_HEADER,
            CRLF
        ]))

    def test_body_response(self) -> None:
        e = HttpRequestRejected(
            status_code=404, reason=b'NOT FOUND',
            body=b'Nothing here')
        self.assertEqual(e.response(self.request), CRLF.join([
            b'HTTP/1.1 404 NOT FOUND',
            PROXY_AGENT_HEADER,
            b'Content-Length: 12',
            CRLF,
            b'Nothing here'
        ]))
