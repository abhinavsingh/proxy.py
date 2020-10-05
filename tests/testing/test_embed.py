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
import time
import unittest
import http.client
import urllib.request
import urllib.error
from typing import Union, Optional
from pathlib import Path

from proxy import TestCase, ReplayTestCase
from proxy.common.constants import DEFAULT_DATA_DIRECTORY_PATH, DEFAULT_TIMEOUT
from proxy.common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, PROXY_AGENT_HEADER_VALUE
from proxy.common.utils import socket_connection, build_http_request, build_http_response
from proxy.http.codes import httpStatusCodes
from proxy.http.methods import httpMethods


@unittest.skipIf(
    os.name == 'nt', 'Disabled for Windows due to weird permission issues.')
class TestReplayTestCase(ReplayTestCase):

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

    def waitCached(self,
                   cache_list_path: Union[str, Path],
                   expected_method: str,
                   expected_host: str,
                   expected_path: str,
                   expected_body: str,
                   timeout: int = DEFAULT_TIMEOUT) -> Optional[str]:
        while timeout > 0:
            try:
                with open(cache_list_path, 'rt') as cache_list:
                    for cache_line in cache_list:
                        method, host, path, body, cache_file_name = cache_line.strip().split(' ')
                        if ((method == expected_method) and (host == expected_host) and
                                (path == expected_path) and (body == expected_body)):
                            return 'proxy-cache-' + cache_file_name
            except FileNotFoundError:
                pass
            time.sleep(1)
            timeout -= 1
        return None

    def test_proxy_replay(self) -> None:
        """With replay enabled, proxy.py will cache responses for all HTTP(s)
        requests made during the test.  When test is re-run, until explicitly
        disabled, proxy.py will replay responses from cache avoiding calls to
        upstream servers.

        This feature only works iff proxy.py is used as a proxy server
        for all HTTP(s) requests made during the test.

        Below we make a HTTP GET request using Python's urllib library."""
        self.make_http_request_using_proxy()

        cache_file_name = self.waitCached(
            os.path.join(DEFAULT_DATA_DIRECTORY_PATH, 'cache', 'list.txt'),
            'GET', 'localhost', '/', 'None', 2)
        if cache_file_name is None:
            self.fail('Timeout waiting for cached request')
        self.assertTrue(
            os.path.isfile(
                os.path.join(DEFAULT_DATA_DIRECTORY_PATH, 'cache', cache_file_name)))

        with open(os.path.join(DEFAULT_DATA_DIRECTORY_PATH, 'cache', cache_file_name), 'rb') as cache_file:
            self.assertEqual(cache_file.read(), build_http_response(
                httpStatusCodes.NOT_FOUND, reason=b'NOT FOUND',
                headers={
                    b'Server': PROXY_AGENT_HEADER_VALUE,
                    b'Connection': b'close'
                }
            ))


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
