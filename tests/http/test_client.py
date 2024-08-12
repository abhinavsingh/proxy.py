# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest

from proxy.http.client import client


class TestClient(unittest.TestCase):

    def test_http(self) -> None:
        response = client(
            host=b'google.com',
            port=80,
            scheme=b'http',
            path=b'/',
            method=b'GET',
            content_type=b'text/html',
        )
        assert response is not None
        self.assertEqual(response.code, b'301')

    def test_client(self) -> None:
        response = client(
            host=b'google.com',
            port=443,
            scheme=b'https',
            path=b'/',
            method=b'GET',
            content_type=b'text/html',
        )
        assert response is not None
        self.assertEqual(response.code, b'301')

    def test_client_connection_refused(self) -> None:
        response = client(
            host=b'cannot-establish-connection.com',
            port=443,
            scheme=b'https',
            path=b'/',
            method=b'GET',
            content_type=b'text/html',
        )
        assert response is None

    def test_cannot_ssl_wrap(self) -> None:
        response = client(
            host=b'example.com',
            port=80,
            scheme=b'https',
            path=b'/',
            method=b'GET',
            content_type=b'text/html',
        )
        assert response is None
