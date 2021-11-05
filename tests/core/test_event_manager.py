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

from proxy.core.event import EventManager


class TestEventManager(unittest.TestCase):

    @mock.patch('proxy.core.event.manager.EventQueue')
    @mock.patch('proxy.core.event.manager.EventDispatcher')
    @mock.patch('proxy.core.event.manager.multiprocessing.Queue')
    @mock.patch('proxy.core.event.manager.threading.Event')
    @mock.patch('proxy.core.event.manager.threading.Thread')
    def test_setup_and_teardown(
            self,
            mock_thread: mock.Mock,
            mock_event: mock.Mock,
            mock_queue: mock.Mock,
            mock_dispatcher: mock.Mock,
            mock_event_queue: mock.Mock,
    ) -> None:
        with EventManager() as _:
            mock_queue.assert_called_once()
            mock_event.assert_called_once()
            mock_thread.assert_called_once_with(
                target=mock_dispatcher.return_value.run,
            )
            mock_thread.return_value.start.assert_called_once()
            mock_event_queue.assert_called_once_with(mock_queue.return_value)
            mock_dispatcher.assert_called_once_with(
                shutdown=mock_event.return_value,
                event_queue=mock_event_queue.return_value,
            )
        mock_event.return_value.set.assert_called_once()
        mock_thread.return_value.join.assert_called_once()
