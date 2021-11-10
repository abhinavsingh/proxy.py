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
import socket
import selectors
import multiprocessing
from unittest import mock

from proxy.core.acceptor import Acceptor
from proxy.common.flag import FlagParser


class TestAcceptor(unittest.TestCase):

    def setUp(self) -> None:
        self.acceptor_id = 1
        self.pipe = multiprocessing.Pipe()
        self.flags = FlagParser.initialize(
            threaded=True, work_klass=mock.MagicMock(),
        )
        self.acceptor = Acceptor(
            idd=self.acceptor_id,
            fd_queue=self.pipe[1],
            flags=self.flags,
            lock=multiprocessing.Lock(),
            executor_queues=[],
            executor_pids=[],
        )

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.core.acceptor.acceptor.recv_handle')
    def test_continues_when_no_events(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        fileno = 10
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock_fromfd.return_value
        mock_fromfd.return_value.accept.return_value = (conn, addr)
        mock_recv_handle.return_value = fileno

        selector = mock_selector.return_value
        selector.select.side_effect = [[], KeyboardInterrupt()]

        self.acceptor.run()

        sock.accept.assert_not_called()
        self.flags.work_klass.assert_not_called()

    @mock.patch('proxy.core.acceptor.executors.TcpClientConnection')
    @mock.patch('threading.Thread')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.core.acceptor.acceptor.recv_handle')
    def test_accepts_client_from_server_socket(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
            mock_thread: mock.Mock,
            mock_client: mock.Mock,
    ) -> None:
        fileno = 10
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock_fromfd.return_value
        mock_fromfd.return_value.accept.return_value = (conn, addr)
        mock_recv_handle.return_value = fileno

        mock_thread.return_value.start.side_effect = KeyboardInterrupt()

        selector = mock_selector.return_value
        selector.select.return_value = [(None, None)]

        self.acceptor.run()

        selector.register.assert_called_with(sock, selectors.EVENT_READ)
        selector.unregister.assert_called_with(sock)
        mock_recv_handle.assert_called_with(self.pipe[1])
        mock_fromfd.assert_called_with(
            fileno,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )
        self.flags.work_klass.assert_called_with(
            mock_client.return_value,
            flags=self.flags,
            event_queue=None,
        )
        mock_thread.assert_called_with(
            target=self.flags.work_klass.return_value.run,
        )
        mock_thread.return_value.start.assert_called()
        sock.close.assert_called()
