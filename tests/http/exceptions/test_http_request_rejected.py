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

from proxy.http import httpStatusCodes
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.exception import HttpRequestRejected
from proxy.common.constants import CRLF
from proxy.common.utils import build_http_response


class TestHttpRequestRejected(unittest.TestCase):

    def setUp(self) -> None:
        self.request = HttpParser(httpParserTypes.REQUEST_PARSER)

    def test_empty_response(self) -> None:
        e = HttpRequestRejected()
        self.assertEqual(e.response(self.request), None)

    def test_status_code_response(self) -> None:
        e = HttpRequestRejected(status_code=200, reason=b'OK')
        self.assertEqual(
            e.response(self.request), CRLF.join([
                b'HTTP/1.1 200 OK',
                CRLF,
            ]),
        )

    def test_body_response(self) -> None:
        e = HttpRequestRejected(
            status_code=httpStatusCodes.NOT_FOUND, reason=b'NOT FOUND',
            body=b'Nothing here',
        )
        self.assertEqual(
            e.response(self.request),
            build_http_response(
                httpStatusCodes.NOT_FOUND,
                reason=b'NOT FOUND', body=b'Nothing here',
            ),
        )
