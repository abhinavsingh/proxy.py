# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import unittest
import http.client
import urllib.request
import urllib.error
from pathlib import Path

from proxy import TestCase
from proxy.common.constants import DEFAULT_DATA_DIRECTORY_PATH
from proxy.common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, PROXY_AGENT_HEADER_VALUE
from proxy.common.utils import socket_connection, build_http_request, build_http_response
from proxy.http.codes import httpStatusCodes
from proxy.http.methods import httpMethods


@unittest.skipIf(
    os.name == 'nt', 'Disabled for Windows due to weird permission issues.')
class TestProxyPyEmbedded(TestCase):
    """This test case is a demonstration of proxy.TestCase and also serves as
    integration test suite for proxy.py."""

    PROXY_PY_STARTUP_FLAGS = TestCase.DEFAULT_PROXY_PY_STARTUP_FLAGS + [
        '--enable-web-server',
    ]

    def tearDown(self) -> None:
        # Delete cache plugin data
        cacheDir = Path(os.path.join(DEFAULT_DATA_DIRECTORY_PATH, 'cache'))
        for f in cacheDir.glob('*'):
            if f.is_file():
                os.remove(f)

    def make_http_request_using_proxy(self) -> None:
        proxy_handler = urllib.request.ProxyHandler({
            'http': 'http://localhost:%d' % self.PROXY_PORT,
        })
        opener = urllib.request.build_opener(proxy_handler)
        with self.assertRaises(urllib.error.HTTPError):
            r: http.client.HTTPResponse = opener.open(
                'http://localhost:%d/' %
                self.PROXY_PORT, timeout=10)
            self.assertEqual(r.status, 404)
            self.assertEqual(r.headers.get('server'), PROXY_AGENT_HEADER_VALUE)
            self.assertEqual(r.headers.get('connection'), b'close')

    def test_with_proxy(self) -> None:
        """Makes a HTTP request to in-build web server via proxy server."""
        with socket_connection(('localhost', self.PROXY_PORT)) as conn:
            conn.send(
                build_http_request(
                    httpMethods.GET, b'http://localhost:%d/' % self.PROXY_PORT,
                    headers={
                        b'Host': b'localhost:%d' % self.PROXY_PORT,
                    })
            )
            response = conn.recv(DEFAULT_CLIENT_RECVBUF_SIZE)
        self.assertEqual(
            response,
            build_http_response(
                httpStatusCodes.NOT_FOUND, reason=b'NOT FOUND',
                headers={
                    b'Server': PROXY_AGENT_HEADER_VALUE,
                    b'Connection': b'close'
                }
            )
        )
