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

from proxy.core.listener import ListenerPool
from proxy.common.flag import FlagParser


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
