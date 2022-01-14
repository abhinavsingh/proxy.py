# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import selectors

import pytest
import unittest
from unittest import mock

from pytest_mock import MockerFixture

from proxy.core.connection import UpstreamConnectionPool


class TestConnectionPool(unittest.TestCase):

    @mock.patch('proxy.core.connection.pool.TcpServerConnection')
    def test_acquire_and_retain_and_reacquire(self, mock_tcp_server_connection: mock.Mock) -> None:
        pool = UpstreamConnectionPool()
        # Mock
        mock_conn = mock_tcp_server_connection.return_value
        addr = mock_conn.addr
        mock_conn.is_reusable.side_effect = [
            True,
        ]
        mock_conn.closed = False
        # Acquire
        created, conn = pool.acquire(addr)
        mock_tcp_server_connection.assert_called_once_with(addr[0], addr[1])
        mock_conn.mark_inuse.assert_called_once()
        mock_conn.reset.assert_not_called()
        self.assertTrue(created)
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        self.assertEqual(len(pool.connections), 1)
        self.assertEqual(pool.connections[conn.connection.fileno()], mock_conn)
        # Retail
        pool.retain(conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        mock_conn.reset.assert_called_once()
        # Reacquire
        created, conn = pool.acquire(addr)
        self.assertFalse(created)
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])

    @mock.patch('proxy.core.connection.pool.TcpServerConnection')
    def test_closed_connections_are_removed_on_release(
            self, mock_tcp_server_connection: mock.Mock,
    ) -> None:
        pool = UpstreamConnectionPool()
        # Mock
        mock_conn = mock_tcp_server_connection.return_value
        mock_conn.closed = True
        addr = mock_conn.addr
        # Acquire
        created, conn = pool.acquire(addr)
        self.assertTrue(created)
        mock_tcp_server_connection.assert_called_once_with(addr[0], addr[1])
        self.assertEqual(conn, mock_conn)
        self.assertEqual(len(pool.pools[addr]), 1)
        self.assertTrue(conn in pool.pools[addr])
        # Release
        mock_conn.is_reusable.return_value = False
        pool.release(conn)
        self.assertEqual(len(pool.pools[addr]), 0)
        # Acquire
        created, conn = pool.acquire(addr)
        self.assertTrue(created)
        self.assertEqual(mock_tcp_server_connection.call_count, 2)


class TestConnectionPoolAsync:

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_get_events(self, mocker: MockerFixture) -> None:
        mock_tcp_server_connection = mocker.patch(
            'proxy.core.connection.pool.TcpServerConnection',
        )
        pool = UpstreamConnectionPool()
        mock_conn = mock_tcp_server_connection.return_value
        addr = mock_conn.addr
        pool.add(addr)
        mock_tcp_server_connection.assert_called_once_with(addr[0], addr[1])
        mock_conn.connect.assert_called_once()
        events = await pool.get_events()
        print(events)
        assert events == {
            mock_conn.connection.fileno.return_value: selectors.EVENT_READ,
        }
        assert pool.pools[addr].pop() == mock_conn
        assert len(pool.pools[addr]) == 0
        assert pool.connections[mock_conn.connection.fileno.return_value] == mock_conn

    @pytest.mark.asyncio    # type: ignore[misc]
    async def test_handle_events(self, mocker: MockerFixture) -> None:
        mock_tcp_server_connection = mocker.patch(
            'proxy.core.connection.pool.TcpServerConnection',
        )
        pool = UpstreamConnectionPool()
        mock_conn = mock_tcp_server_connection.return_value
        addr = mock_conn.addr
        pool.add(addr)
        assert len(pool.pools[addr]) == 1
        assert len(pool.connections) == 1
        await pool.handle_events([mock_conn.connection.fileno.return_value], [])
        assert len(pool.pools[addr]) == 0
        assert len(pool.connections) == 0
