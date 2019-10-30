# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import unittest
import socket
import selectors
import multiprocessing
from unittest import mock

from proxy.common.flags import Flags
from proxy.core.acceptor import Acceptor


class TestAcceptor(unittest.TestCase):

    def setUp(self) -> None:
        self.acceptor_id = 1
        self.mock_protocol_handler = mock.MagicMock()
        self.pipe = multiprocessing.Pipe()
        self.flags = Flags()
        self.acceptor = Acceptor(
            idd=self.acceptor_id,
            work_queue=self.pipe[1],
            flags=self.flags,
            work_klass=self.mock_protocol_handler)

    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.core.acceptor.recv_handle')
    def test_continues_when_no_events(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock) -> None:
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
        self.mock_protocol_handler.assert_not_called()

    @mock.patch('threading.Thread')
    @mock.patch('selectors.DefaultSelector')
    @mock.patch('socket.fromfd')
    @mock.patch('proxy.core.acceptor.recv_handle')
    def test_accepts_client_from_server_socket(
            self,
            mock_recv_handle: mock.Mock,
            mock_fromfd: mock.Mock,
            mock_selector: mock.Mock,
            mock_thread: mock.Mock) -> None:
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
            type=socket.SOCK_STREAM
        )
        self.mock_protocol_handler.assert_called_with(
            fileno=conn.fileno(),
            addr=addr,
            flags=self.flags,
            event_queue=None,
        )
        mock_thread.assert_called_with(
            target=self.mock_protocol_handler.return_value.run)
        mock_thread.return_value.start.assert_called()
        sock.close.assert_called()
