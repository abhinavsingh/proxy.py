# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import httpx

from proxy import TestCase


class TestHttp2WithProxy(TestCase):

    def test_http2_via_proxy(self) -> None:
        assert self.PROXY
        response = httpx.get(
            "https://www.google.com",
            headers={"accept": "application/json"},
            verify=httpx.create_ssl_context(http2=True),
            timeout=httpx.Timeout(timeout=5.0),
            proxies={
                "all://": "http://localhost:%d" % self.PROXY.flags.port,
            },
        )
        self.assertEqual(response.status_code, 200)

    # def test_http2_streams_over_proxy_keep_alive_connection(self) -> None:
    #     pass
