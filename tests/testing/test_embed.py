# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import http.client
import urllib.request
import urllib.error

import pytest

from proxy import TestCase
from proxy.common._compat import IS_WINDOWS  # noqa: WPS436
from proxy.common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, PROXY_AGENT_HEADER_VALUE
from proxy.common.utils import socket_connection, build_http_request
from proxy.http import httpMethods
from proxy.http.responses import NOT_FOUND_RESPONSE_PKT


@pytest.mark.skipif(
    IS_WINDOWS,
    reason='Disabled for Windows due to weird permission issues.',
)
class TestProxyPyEmbedded(TestCase):
    """This test case is a demonstration of proxy.TestCase and also serves as
    integration test suite for proxy.py."""

    PROXY_PY_STARTUP_FLAGS = TestCase.DEFAULT_PROXY_PY_STARTUP_FLAGS + [
        '--enable-web-server',
    ]

    def test_with_proxy(self) -> None:
        """Makes a HTTP request to in-build web server via proxy server."""
        assert self.PROXY
        with socket_connection(('localhost', self.PROXY.flags.port)) as conn:
            conn.send(
                build_http_request(
                    httpMethods.GET, b'http://localhost:%d/' % self.PROXY.flags.port,
                    headers={
                        b'Host': b'localhost:%d' % self.PROXY.flags.port,
                    },
                ),
            )
            response = conn.recv(DEFAULT_CLIENT_RECVBUF_SIZE)
        self.assertEqual(
            response,
            NOT_FOUND_RESPONSE_PKT.tobytes(),
        )

    def test_proxy_vcr(self) -> None:
        """With VCR enabled, proxy.py will cache responses for all HTTP(s)
        requests made during the test.  When test is re-run, until explicitly
        disabled, proxy.py will replay responses from cache avoiding calls to
        upstream servers.

        This feature only works iff proxy.py is used as a proxy server
        for all HTTP(s) requests made during the test.

        Below we make a HTTP GET request using Python's urllib library."""
        with self.vcr():
            self.make_http_request_using_proxy()

    def test_proxy_no_vcr(self) -> None:
        self.make_http_request_using_proxy()

    def make_http_request_using_proxy(self) -> None:
        assert self.PROXY and self.PROXY.acceptors
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'http://localhost:%d' % self.PROXY.flags.port,
        })
        opener = urllib.request.build_opener(proxy_handler)
        with self.assertRaises(urllib.error.HTTPError):
            r: http.client.HTTPResponse = opener.open(
                'http://localhost:%d/' %
                self.PROXY.flags.port, timeout=10,
            )
            self.assertEqual(r.status, 404)
            self.assertEqual(r.headers.get('server'), PROXY_AGENT_HEADER_VALUE)
            self.assertEqual(r.headers.get('connection'), b'close')
