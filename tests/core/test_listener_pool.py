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
import pytest
import tempfile
import unittest
from unittest import mock

from proxy.common.flag import FlagParser
from proxy.core.listener import ListenerPool
from proxy.common.constants import IS_WINDOWS


class TestListenerPool(unittest.TestCase):

    @mock.patch('proxy.core.listener.pool.TcpSocketListener')
    @mock.patch('proxy.core.listener.pool.UnixSocketListener')
    def test_setup_and_teardown(
            self,
            mock_unix_listener: mock.Mock,
            mock_tcp_listener: mock.Mock,
    ) -> None:
        flags = FlagParser.initialize(port=0)
        with ListenerPool(flags=flags) as pool:
            mock_tcp_listener.assert_called_once_with(flags=flags)
            mock_unix_listener.assert_not_called()
            mock_tcp_listener.return_value.setup.assert_called_once()
            self.assertEqual(pool.pool[0], mock_tcp_listener.return_value)
        mock_tcp_listener.return_value.shutdown.assert_called_once()

    @pytest.mark.skipif(
        IS_WINDOWS,
        reason='AF_UNIX not available on Windows',
    )  # type: ignore[misc]
    @mock.patch('proxy.core.listener.pool.TcpSocketListener')
    @mock.patch('proxy.core.listener.pool.UnixSocketListener')
    def test_unix_socket_listener(
            self,
            mock_unix_listener: mock.Mock,
            mock_tcp_listener: mock.Mock,
    ) -> None:
        flags = FlagParser.initialize(
            unix_socket_path=os.path.join(tempfile.gettempdir(), 'proxy.sock'),
        )
        with ListenerPool(flags=flags) as pool:
            mock_unix_listener.assert_called_once_with(flags=flags)
            mock_tcp_listener.assert_not_called()
            mock_unix_listener.return_value.setup.assert_called_once()
            self.assertEqual(pool.pool[0], mock_unix_listener.return_value)
        mock_unix_listener.return_value.shutdown.assert_called_once()

    @mock.patch('proxy.core.listener.pool.TcpSocketListener')
    @mock.patch('proxy.core.listener.pool.UnixSocketListener')
    def test_multi_listener_on_ports(
            self,
            mock_unix_listener: mock.Mock,
            mock_tcp_listener: mock.Mock,
    ) -> None:
        flags = FlagParser.initialize(
            ['--ports', '9000', '--ports', '9001'],
            port=0,
        )
        with ListenerPool(flags=flags) as pool:
            mock_unix_listener.assert_not_called()
            self.assertEqual(len(pool.pool), 3)
            self.assertEqual(mock_tcp_listener.call_count, 3)
            self.assertEqual(
                mock_tcp_listener.call_args_list[0][1]['flags'],
                flags,
            )
            self.assertEqual(
                mock_tcp_listener.call_args_list[1][1]['flags'],
                flags,
            )
            self.assertEqual(
                mock_tcp_listener.call_args_list[1][1]['port'],
                9000,
            )
            self.assertEqual(
                mock_tcp_listener.call_args_list[2][1]['flags'],
                flags,
            )
            self.assertEqual(
                mock_tcp_listener.call_args_list[2][1]['port'],
                9001,
            )
