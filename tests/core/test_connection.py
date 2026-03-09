# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

import unittest
from unittest import mock

from proxy.common.types import TcpOrTlsSocket
from proxy.core.connection import (
    TcpConnection, TcpClientConnection, TcpServerConnection,
    Socks5ServerConnection, TcpConnectionUninitializedException,
    tcpConnectionTypes,
)
from proxy.common.constants import (
    DEFAULT_PORT, DEFAULT_IPV4_HOSTNAME, DEFAULT_IPV6_HOSTNAME,
)


class TestTcpConnection(unittest.TestCase):
    class TcpConnectionToTest(TcpConnection):

        def __init__(
            self, conn: Optional[TcpOrTlsSocket] = None,
            tag: int = tcpConnectionTypes.CLIENT,
        ) -> None:
            super().__init__(tag)
            self._conn = conn

        @property
        def connection(self) -> TcpOrTlsSocket:
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
    def testTcpServerWillNotIgnoreDoubleConnectAttemptsSilently(
            self,
            mock_new_socket_connection: mock.Mock,
    ) -> None:
        conn = TcpServerConnection(
            str(DEFAULT_IPV6_HOSTNAME), DEFAULT_PORT,
        )
        conn.connect()
        with self.assertRaises(AssertionError):
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


class TestSocks5ServerConnection(unittest.TestCase):

    def testInitWithBasicParams(self) -> None:
        conn = Socks5ServerConnection('127.0.0.1', 1080)
        self.assertEqual(conn.addr, ('127.0.0.1', 1080, None, None))
        self.assertTrue(conn.closed)
        self.assertEqual(conn.tag, 'server')

    def testInitWithAuthParams(self) -> None:
        conn = Socks5ServerConnection(
            '127.0.0.1', 1080,
            username='user', password='pass',
        )
        self.assertEqual(conn.addr, ('127.0.0.1', 1080, 'user', 'pass'))
        self.assertTrue(conn.closed)

    def testRaisesTcpConnectionUninitializedException(self) -> None:
        conn = Socks5ServerConnection('127.0.0.1', 1080)
        with self.assertRaises(TcpConnectionUninitializedException):
            _ = conn.connection

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectWithoutAuth(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        target_addr = ('target.example.com', 80)
        conn.connect(addr=target_addr)

        mock_socksocket.assert_called_once()
        mock_sock.set_proxy.assert_called_once_with(
            proxy_type=2,
            addr='proxy.example.com',
            port=1080,
            username=None,
            password=None,
        )
        mock_sock.connect.assert_called_once_with(target_addr)
        mock_sock.setblocking.assert_called_once_with(False)
        self.assertFalse(conn.closed)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectWithAuth(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection(
            'proxy.example.com', 1080,
            username='testuser', password='testpass',
        )
        target_addr = ('target.example.com', 443)
        conn.connect(addr=target_addr)

        mock_sock.set_proxy.assert_called_once_with(
            proxy_type=2,
            addr='proxy.example.com',
            port=1080,
            username='testuser',
            password='testpass',
        )
        self.assertFalse(conn.closed)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectWillNotIgnoreDoubleConnectAttempts(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        with self.assertRaises(AssertionError):
            conn.connect(addr=('target.example.com', 80))

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectionProperty(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        self.assertEqual(conn.connection, mock_sock)

    def testClose(self) -> None:
        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn._conn = mock.MagicMock()
        conn.closed = False

        conn.close()
        conn._conn.close.assert_called_once()
        self.assertTrue(conn.closed)

    def testCloseNoOpIfAlreadyClosed(self) -> None:
        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn._conn = mock.MagicMock()
        conn.closed = True

        conn.close()
        conn._conn.close.assert_not_called()
        self.assertTrue(conn.closed)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testRecvReturnsData(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.recv.return_value = b'test data'
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        result = conn.recv()
        self.assertIsNotNone(result)
        self.assertEqual(result.tobytes(), b'test data')

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testRecvReturnsEmptyOnBlockingIOError(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.recv.side_effect = BlockingIOError()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        result = conn.recv()
        self.assertIsNotNone(result)
        self.assertEqual(result.tobytes(), b'')

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testRecvReturnsNoneOnEmptyData(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.recv.return_value = b''
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        result = conn.recv()
        self.assertIsNone(result)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testSend(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.send.return_value = 10
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        result = conn.send(b'test data')
        self.assertEqual(result, 10)
        mock_sock.send.assert_called_once_with(b'test data')

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testSendWithMemoryView(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.send.return_value = 9
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        data = memoryview(b'test data')
        result = conn.send(data)
        self.assertEqual(result, 9)
        mock_sock.send.assert_called_once_with(data)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testRecvWithCustomBufferSize(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_sock.recv.return_value = b'x' * 4096
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect(addr=('target.example.com', 80))

        result = conn.recv(buffer_size=4096)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 4096)
        mock_sock.recv.assert_called_once_with(4096)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectWithSourceAddress(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        source_addr = ('192.168.1.100', 0)
        target_addr = ('target.example.com', 80)
        conn.connect(addr=target_addr, source_address=source_addr)

        mock_sock.connect.assert_called_once_with(target_addr)

    @mock.patch('proxy.core.connection.server.socks.socksocket')
    def testConnectWithoutAddrParameter(self, mock_socksocket: mock.Mock) -> None:
        mock_sock = mock.MagicMock()
        mock_socksocket.return_value = mock_sock

        conn = Socks5ServerConnection('proxy.example.com', 1080)
        conn.connect()

        mock_sock.connect.assert_called_once()
