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
import tempfile
import ipaddress
import itertools

import pytest
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
        flags = FlagParser.initialize()
        with ListenerPool(flags=flags) as pool:
            mock_tcp_listener.assert_called_once_with(flags=flags, hostname=flags.hostname, port=flags.port)
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
    def test_multi_listener(
            self,
            mock_unix_listener: mock.Mock,
            mock_tcp_listener: mock.Mock,
    ) -> None:
        flags = FlagParser.initialize(
            ['--hostnames', '127.0.0.2', '--ports', '9000', '--ports', '9001'],
        )
        with ListenerPool(flags=flags) as pool:
            mock_unix_listener.assert_not_called()
            self.assertEqual(len(pool.pool), 6)
            self.assertEqual(mock_tcp_listener.call_count, 6)
            self.assertSetEqual(
                {
                    (
                        mock_tcp_listener.call_args_list[call][1]['hostname'],
                        mock_tcp_listener.call_args_list[call][1]['port'],
                    ) for call in range(6)
                },
                set(
                    itertools.product(
                        [ipaddress.IPv4Address('127.0.0.1'), ipaddress.IPv4Address('127.0.0.2')],
                        [8899, 9000, 9001],
                    ),
                ),
            )
            self.assertListEqual(
                [mock_tcp_listener.call_args_list[call][1]['flags'] for call in range(6)],
                [flags, flags, flags, flags, flags, flags],
            )
