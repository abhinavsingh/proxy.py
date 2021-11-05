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

from proxy.common.flag import FlagParser
from proxy.core.acceptor import AcceptorPool


class TestAcceptorPool(unittest.TestCase):

    @mock.patch('proxy.core.acceptor.pool.send_handle')
    @mock.patch('multiprocessing.Pipe')
    @mock.patch('proxy.core.acceptor.pool.Acceptor')
    @mock.patch('proxy.core.acceptor.Listener')
    def test_setup_and_shutdown(
            self,
            mock_listener: mock.Mock,
            mock_acceptor: mock.Mock,
            mock_pipe: mock.Mock,
            mock_send_handle: mock.Mock,
    ) -> None:
        acceptor1 = mock.MagicMock()
        acceptor2 = mock.MagicMock()
        mock_acceptor.side_effect = [acceptor1, acceptor2]

        num_acceptors = 2
        flags = FlagParser.initialize(
            num_acceptors=num_acceptors,
            threaded=True,
        )
        self.assertEqual(flags.num_acceptors, num_acceptors)

        pool = AcceptorPool(
            flags=flags, listener=mock_listener.return_value,
            executor_queues=[], executor_pids=[],
        )
        pool.setup()

        self.assertEqual(mock_pipe.call_count, num_acceptors)
        self.assertEqual(mock_acceptor.call_count, num_acceptors)
        mock_send_handle.assert_called()
        self.assertEqual(mock_send_handle.call_count, num_acceptors)

        self.assertEqual(
            mock_acceptor.call_args_list[0][1]['idd'], 0,
        )
        self.assertEqual(
            mock_acceptor.call_args_list[0][1]['fd_queue'], mock_pipe.return_value[1],
        )
        self.assertEqual(
            mock_acceptor.call_args_list[0][1]['flags'], flags,
        )
        self.assertEqual(
            mock_acceptor.call_args_list[0][1]['event_queue'], None,
        )
        # executor_queues=[],
        # executor_pids=[]
        self.assertEqual(
            mock_acceptor.call_args_list[1][1]['idd'], 1,
        )

        acceptor1.start.assert_called_once()
        acceptor2.start.assert_called_once()
        mock_listener.return_value.fileno.assert_called_once()

        acceptor1.join.assert_not_called()
        acceptor2.join.assert_not_called()

        pool.shutdown()
        acceptor1.join.assert_called_once()
        acceptor2.join.assert_called_once()
