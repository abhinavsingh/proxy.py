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
from proxy.core.acceptor import Acceptor, AcceptorPool


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


class TestAcceptorPool(unittest.TestCase):

    @mock.patch('proxy.core.acceptor.send_handle')
    @mock.patch('multiprocessing.Pipe')
    @mock.patch('socket.socket')
    @mock.patch('proxy.core.acceptor.Acceptor')
    def test_setup_and_shutdown(
            self,
            mock_worker: mock.Mock,
            mock_socket: mock.Mock,
            mock_pipe: mock.Mock,
            _mock_send_handle: mock.Mock) -> None:
        mock_worker1 = mock.MagicMock()
        mock_worker2 = mock.MagicMock()
        mock_worker.side_effect = [mock_worker1, mock_worker2]

        num_workers = 2
        sock = mock_socket.return_value
        work_klass = mock.MagicMock()
        flags = Flags(num_workers=2)
        acceptor = AcceptorPool(flags=flags, work_klass=work_klass)

        acceptor.setup()

        work_klass.assert_not_called()
        mock_socket.assert_called_with(
            socket.AF_INET6 if acceptor.flags.hostname.version == 6 else socket.AF_INET,
            socket.SOCK_STREAM
        )
        sock.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind.assert_called_with(
            (str(acceptor.flags.hostname), acceptor.flags.port))
        sock.listen.assert_called_with(acceptor.flags.backlog)
        sock.setblocking.assert_called_with(False)

        self.assertTrue(mock_pipe.call_count, num_workers)
        self.assertTrue(mock_worker.call_count, num_workers)
        mock_worker1.start.assert_called()
        mock_worker1.join.assert_not_called()
        mock_worker2.start.assert_called()
        mock_worker2.join.assert_not_called()

        sock.close.assert_called()

        acceptor.shutdown()
        mock_worker1.join.assert_called()
        mock_worker2.join.assert_called()
