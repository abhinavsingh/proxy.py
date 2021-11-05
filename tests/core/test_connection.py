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
import ssl
from typing import Optional, Union

import unittest
from unittest import mock

from proxy.common.constants import DEFAULT_IPV4_HOSTNAME, DEFAULT_IPV6_HOSTNAME, DEFAULT_PORT
from proxy.core.connection import TcpClientConnection, TcpConnection, TcpConnectionUninitializedException, TcpServerConnection
from proxy.core.connection import tcpConnectionTypes


class TestTcpConnection(unittest.TestCase):
    class TcpConnectionToTest(TcpConnection):

        def __init__(
            self, conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None,
            tag: int = tcpConnectionTypes.CLIENT,
        ) -> None:
            super().__init__(tag)
            self._conn = conn

        @property
        def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
            if self._conn is None:
                raise TcpConnectionUninitializedException()
            return self._conn

    def testThrowsKeyErrorIfNoConn(self) -> None:
        self.conn = TestTcpConnection.TcpConnectionToTest()
        with self.assertRaises(TcpConnectionUninitializedException):
            self.conn.send(b'dummy')
        with self.assertRaises(TcpConnectionUninitializedException):
            self.conn.recv()
        with self.assertRaises(TcpConnectionUninitializedException):
            self.conn.close()

    def testClosesIfNotClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.close()
        _conn.close.assert_called()
        self.assertTrue(self.conn.closed)

    def testNoOpIfAlreadyClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.closed = True
        self.conn.close()
        _conn.close.assert_not_called()
        self.assertTrue(self.conn.closed)

    def testFlushReturnsIfNoBuffer(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.flush()
        self.assertTrue(not _conn.send.called)

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv6Connection(
            self, mock_socket: mock.Mock,
    ) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT,
        )
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT, 0, 0),
        )

    @mock.patch('proxy.core.connection.server.new_socket_connection')
    def testTcpServerIgnoresDoubleConnectSilently(
            self,
            mock_new_socket_connection: mock.Mock,
    ) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT,
        )
        conn.connect()
        conn.connect()
        mock_new_socket_connection.assert_called_once()

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv4Connection(
            self, mock_socket: mock.Mock,
    ) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV4_HOSTNAME), DEFAULT_PORT,
        )
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(DEFAULT_IPV4_HOSTNAME), DEFAULT_PORT),
        )

    @mock.patch('proxy.core.connection.server.new_socket_connection')
    def testTcpServerConnectionProperty(
            self,
            mock_new_socket_connection: mock.Mock,
    ) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT,
        )
        conn.connect()
        self.assertEqual(
            conn.connection,
            mock_new_socket_connection.return_value,
        )

    def testTcpServerRaisesTcpConnectionUninitializedException(self) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT,
        )
        with self.assertRaises(TcpConnectionUninitializedException):
            _ = conn.connection

    def testTcpClientRaisesTcpConnectionUninitializedException(self) -> None:
        _conn = mock.MagicMock()
        _addr = mock.MagicMock()
        conn = TcpClientConnection(_conn, _addr)
        conn._conn = None
        with self.assertRaises(TcpConnectionUninitializedException):
            _ = conn.connection
