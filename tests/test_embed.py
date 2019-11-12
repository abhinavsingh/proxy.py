# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import socket

from typing import Optional
from contextlib import closing

from proxy.common.constants import DEFAULT_CLIENT_RECVBUF_SIZE, PROXY_AGENT_HEADER_VALUE
from proxy.common.utils import socket_connection, build_http_request, build_http_response
from proxy.http.codes import httpStatusCodes
from proxy.http.methods import httpMethods
from proxy.main import start


def get_available_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return port


class TestProxyPyEmbedded(unittest.TestCase):

    def test_proxy_py_web_server(self) -> None:
        with socket_connection(('localhost', self.port)) as conn:
            conn.send(
                build_http_request(httpMethods.GET, b'/')
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

    def test_proxy_py_proxy_server(self):
        with socket_connection(('localhost', self.port)) as conn:
            conn.send(
                build_http_request(
                    httpMethods.GET, b'http://localhost:%d/' % self.port,
                    headers={b'Host': b'localhost:%d' % self.port})
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

    def run(self, result: Optional[unittest.TestResult] = ...):
        self.port = get_available_port()
        with start([
                '--num-workers', '1',
                '--port', str(self.port),
                '--enable-web-server']):
            super().run(result)
