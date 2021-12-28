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

from unittest import mock

from proxy.core.connection import UpstreamConnectionPool


class TestConnectionPool(unittest.TestCase):

    @mock.patch('proxy.core.connection.pool.TcpServerConnection')
    def test_acquire_and_release_and_reacquire(self, mock_tcp_server_connection: mock.Mock) -> None:
        pool = UpstreamConnectionPool()
        addr = ('localhost', 1234)
        # Mock
        mock_conn = mock_tcp_server_connection.return_value
        mock_conn.is_reusable.side_effect = [
            False, True, True,
        ]
        mock_conn.closed = False
        # Acquire
        created, conn = pool.acquire(*addr)
        self.assertTrue(created)
        mock_tcp_server_connection.assert_called_once_with(*addr)
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        # Release (connection must be retained because not closed)
        pool.release(conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        # Reacquire
        created, conn = pool.acquire(*addr)
        self.assertFalse(created)
        mock_conn.reset.assert_called_once()
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])

    @mock.patch('proxy.core.connection.pool.TcpServerConnection')
    def test_closed_connections_are_removed_on_release(
            self, mock_tcp_server_connection: mock.Mock,
    ) -> None:
        pool = UpstreamConnectionPool()
        addr = ('localhost', 1234)
        # Mock
        mock_conn = mock_tcp_server_connection.return_value
        mock_conn.closed = True
        mock_conn.addr = addr
        # Acquire
        created, conn = pool.acquire(*addr)
        self.assertTrue(created)
        mock_tcp_server_connection.assert_called_once_with(*addr)
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        # Release
        pool.release(conn)
        self.assertEqual(len(pool.pools[addr]), 0)
        # Acquire
        created, conn = pool.acquire(*addr)
        self.assertTrue(created)
        self.assertEqual(mock_tcp_server_connection.call_count, 2)
        mock_conn.is_reusable.assert_not_called()
