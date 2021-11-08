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
import socket
import tempfile
import unittest

from unittest import mock

from proxy.common.utils import bytes_
from proxy.common.flag import FlagParser
from proxy.core.acceptor import AcceptorPool


class TestAcceptorPool(unittest.TestCase):

    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.core.acceptor.pool.send_handle')
    @mock.patch('multiprocessing.Pipe')
    @mock.patch('socket.socket')
    @mock.patch('proxy.core.acceptor.pool.Acceptor')
    def test_setup_and_shutdown(
            self,
            mock_acceptor: mock.Mock,
            mock_socket: mock.Mock,
            mock_pipe: mock.Mock,
            mock_send_handle: mock.Mock,
            mock_open: mock.Mock,
            mock_exists: mock.Mock,
            mock_remove: mock.Mock,
    ) -> None:
        acceptor1 = mock.MagicMock()
        acceptor2 = mock.MagicMock()
        mock_acceptor.side_effect = [acceptor1, acceptor2]

        num_workers = 2
        pid_file = os.path.join(tempfile.gettempdir(), 'pid')
        sock = mock_socket.return_value
        work_klass = mock.MagicMock()
        flags = FlagParser.initialize(
            num_workers=2, pid_file=pid_file, threaded=True,
        )

        pool = AcceptorPool(flags=flags, work_klass=work_klass)
        pool.setup()
        mock_send_handle.assert_called()

        work_klass.assert_not_called()
        mock_socket.assert_called_with(
            socket.AF_INET6 if pool.flags.hostname.version == 6 else socket.AF_INET,
            socket.SOCK_STREAM,
        )
        sock.setsockopt.assert_called_with(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1,
        )
        sock.bind.assert_called_with(
            (str(pool.flags.hostname), 8899),
        )
        sock.listen.assert_called_with(pool.flags.backlog)
        sock.setblocking.assert_called_with(False)

        self.assertTrue(mock_pipe.call_count, num_workers)
        self.assertTrue(mock_acceptor.call_count, num_workers)
        acceptor1.start.assert_called()
        acceptor2.start.assert_called()
        acceptor1.join.assert_not_called()
        acceptor2.join.assert_not_called()

        sock.close.assert_called()

        pool.shutdown()

        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            bytes_(os.getpid()),
        )
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

        acceptor1.join.assert_called()
        acceptor2.join.assert_called()
