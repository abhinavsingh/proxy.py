# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket

import unittest
from unittest import mock

from proxy.common.utils import socket_connection, new_socket_connection
from proxy.common.constants import (
    DEFAULT_PORT, DEFAULT_TIMEOUT, DEFAULT_HTTP_PORT, DEFAULT_IPV4_HOSTNAME,
    DEFAULT_IPV6_HOSTNAME,
)


class TestSocketConnectionUtils(unittest.TestCase):

    def setUp(self) -> None:
        self.addr_ipv4 = (str(DEFAULT_IPV4_HOSTNAME), DEFAULT_PORT)
        self.addr_ipv6 = (str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT)
        self.addr_dual = ('httpbingo.org', DEFAULT_HTTP_PORT)

    @mock.patch('socket.socket')
    def test_new_socket_connection_ipv4(self, mock_socket: mock.Mock) -> None:
        conn = new_socket_connection(self.addr_ipv4)
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.assertEqual(conn, mock_socket.return_value)
        mock_socket.return_value.connect.assert_called_with(self.addr_ipv4)

    @mock.patch('socket.socket')
    def test_new_socket_connection_ipv6(self, mock_socket: mock.Mock) -> None:
        conn = new_socket_connection(self.addr_ipv6)
        mock_socket.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM, 0)
        self.assertEqual(conn, mock_socket.return_value)
        mock_socket.return_value.connect.assert_called_with(
            (self.addr_ipv6[0], self.addr_ipv6[1], 0, 0),
        )

    @mock.patch('socket.create_connection')
    def test_new_socket_connection_dual(self, mock_socket: mock.Mock) -> None:
        conn = new_socket_connection(self.addr_dual)
        mock_socket.assert_called_with(
            self.addr_dual, timeout=DEFAULT_TIMEOUT, source_address=None,
        )
        self.assertEqual(conn, mock_socket.return_value)

    @mock.patch('proxy.common.utils.new_socket_connection')
    def test_decorator(self, mock_new_socket_connection: mock.Mock) -> None:
        @socket_connection(self.addr_ipv4)
        def dummy(conn: socket.socket) -> None:
            self.assertEqual(conn, mock_new_socket_connection.return_value)
        dummy()     # type: ignore

    @mock.patch('proxy.common.utils.new_socket_connection')
    def test_context_manager(
            self, mock_new_socket_connection: mock.Mock,
    ) -> None:
        with socket_connection(self.addr_ipv4) as conn:
            self.assertEqual(conn, mock_new_socket_connection.return_value)
