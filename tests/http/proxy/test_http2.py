# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import sys
from typing import Any, Dict

import httpx

from proxy import TestCase


class TestHttp2WithProxy(TestCase):

    def test_http2_via_proxy(self) -> None:
        assert self.PROXY
        proxy_url = 'http://localhost:%d' % self.PROXY.flags.port
        proxies: Dict[str, Any] = (
            {
                'proxies': {
                    'all://': proxy_url,
                },
            }
            # For Python>=3.11, proxies keyword is deprecated by httpx
            if sys.version_info < (3, 11, 0)
            else {'proxy': proxy_url}
        )
        response = httpx.get(
            'https://www.google.com',
            headers={'accept': 'application/json'},
            verify=httpx.create_ssl_context(http2=True),
            timeout=httpx.Timeout(timeout=5.0),
            **proxies,
        )
        self.assertEqual(response.status_code, 200)

    # def test_http2_streams_over_proxy_keep_alive_connection(self) -> None:
    #     pass
