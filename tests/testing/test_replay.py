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
import sys
import unittest
import http.client
import urllib.request
import urllib.error
from pathlib import Path

from proxy import ReplayTestCase
from proxy.common.constants import PROXY_AGENT_HEADER_VALUE
from proxy.common.utils import build_http_response
from proxy.http.parser import HttpParser
from proxy.http.codes import httpStatusCodes


@unittest.skipIf(
    os.name == 'nt', 'Disabled for Windows due to weird permission issues.')
class TestReplayTestCase(ReplayTestCase):

    PROXY_PY_STARTUP_FLAGS = ReplayTestCase.DEFAULT_PROXY_PY_STARTUP_FLAGS + [
        '--enable-web-server',
    ]

    def tearDown(self) -> None:
        # Delete cache plugin data
        assert self.PROXY is not None
        cacheDir = Path(self.PROXY.flags.cache_dir)
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
                'http://localhost:%d/' % self.PROXY_PORT,
                timeout=10)
            self.assertEqual(r.status, 404)
            self.assertEqual(r.headers.get('server'), PROXY_AGENT_HEADER_VALUE)
            self.assertEqual(r.headers.get('connection'), b'close')

    def test_proxy_replay(self) -> None:
        """With replay enabled, proxy.py will cache responses for all HTTP(s)
        requests made during the test.  When test is re-run, until explicitly
        disabled, proxy.py will replay responses from cache avoiding calls to
        upstream servers.

        This feature only works iff proxy.py is used as a proxy server
        for all HTTP(s) requests made during the test.

        Below we make a HTTP GET request using Python's urllib library."""
        self.make_http_request_using_proxy()

        # This is roughly the request made by urllib
        request = HttpParser.request(
            b'GET http://localhost:%d/ HTTP/1.1\r\n' % self.PROXY_PORT +
            b'Accept-Encoding: identity\r\n' +
            b'Host: localhost:%d\r\n' % self.PROXY_PORT +
            b'User-Agent: Python-urllib/%d.%d\r\n' % (sys.version_info[0], sys.version_info[1]) +
            b'Connection: close\r\n\r\n')

        assert self.PROXY is not None
        cache_file_path = os.path.join(
            self.PROXY.flags.cache_dir,
            '.'.join([request.fingerprint(), 'cache']))
        self.assertTrue(os.path.isfile(cache_file_path))
        with open(cache_file_path, 'rb') as cache_file:
            self.assertEqual(cache_file.read(), build_http_response(
                httpStatusCodes.NOT_FOUND, reason=b'NOT FOUND',
                headers={
                    b'Server': PROXY_AGENT_HEADER_VALUE,
                    b'Connection': b'close'
                }
            ))
