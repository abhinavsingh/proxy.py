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
import multiprocessing

import unittest
from unittest import mock

from proxy.common.flag import FlagParser
from proxy.core.acceptor import Acceptor


class TestAcceptor(unittest.TestCase):

    def setUp(self) -> None:
        self.acceptor_id = 1
        self.pipe = mock.MagicMock()
        self.work_klass = mock.MagicMock()
        self.flags = FlagParser.initialize(
            threaded=True,
            work_klass=self.work_klass,
            local_executor=0,
        )
        self.acceptor = Acceptor(
            idd=self.acceptor_id,
            fd_queue=self.pipe[1],
            flags=self.flags,
            lock=multiprocessing.Lock(),
            executor_queues=[],
            executor_pids=[],
            executor_locks=[],
        )

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.socket')
    @mock.patch('socket.dup')
    @mock.patch('proxy.core.acceptor.acceptor.recv_handle')
    def test_continues_when_no_events(
            self,
            mock_recv_handle: mock.Mock,
            mock_socket_dup: mock.Mock,
            mock_socket: mock.Mock,
            mock_selector: mock.Mock,
    ) -> None:
        fileno = 10
        mock_socket_dup.side_effect = lambda fd: fd
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock.MagicMock()
        sock.accept.return_value = (conn, addr)
        mock_socket.side_effect = lambda **kwargs: sock if kwargs.get('fileno') == fileno else mock.DEFAULT
        mock_recv_handle.return_value = fileno

        selector = mock_selector.return_value
        selector.select.side_effect = [[], KeyboardInterrupt()]

        self.acceptor.run()

        sock.accept.assert_not_called()
        self.flags.work_klass.assert_not_called()

    @mock.patch('threading.Thread')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.dup')
    @mock.patch('socket.socket')
    @mock.patch('proxy.core.acceptor.acceptor.recv_handle')
    def test_accepts_client_from_server_socket(
            self,
            mock_recv_handle: mock.Mock,
            mock_socket: mock.Mock,
            mock_socket_dup: mock.Mock,
            mock_selector: mock.Mock,
            mock_thread: mock.Mock,
    ) -> None:
        fileno = 10
        mock_socket_dup.side_effect = lambda fd: fd
        conn = mock.MagicMock()
        addr = mock.MagicMock()
        sock = mock.MagicMock()
        sock.accept.return_value = (conn, addr)
        mock_socket.side_effect = lambda **kwargs: sock if kwargs.get('fileno') == fileno else mock.DEFAULT
        mock_recv_handle.return_value = fileno

        self.pipe[1].recv.return_value = 1

        mock_thread.return_value.start.side_effect = KeyboardInterrupt()

        mock_key = mock.MagicMock()
        type(mock_key).data = mock.PropertyMock(return_value=fileno)

        selector = mock_selector.return_value
        selector.select.return_value = [(mock_key, selectors.EVENT_READ)]

        self.acceptor.run()

        self.pipe[1].recv.assert_called_once()
        selector.register.assert_called_with(
            fileno, selectors.EVENT_READ, fileno,
        )
        selector.unregister.assert_called_with(fileno)
        mock_recv_handle.assert_called_with(self.pipe[1])
        mock_socket.assert_called_with(
            fileno=fileno,
        )
        self.flags.work_klass.assert_called_with(
            self.work_klass.create.return_value,
            flags=self.flags,
            event_queue=None,
            upstream_conn_pool=None,
        )
        mock_thread.assert_called_with(
            target=self.flags.work_klass.return_value.run,
        )
        mock_thread.return_value.start.assert_called()
        sock.close.assert_called()
