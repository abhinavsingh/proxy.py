# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import multiprocessing
import os
import threading
import unittest
import queue

from unittest import mock

from proxy.common.types import DictQueueType
from proxy.core.event import EventDispatcher, EventQueue, eventNames


class TestEventDispatcher(unittest.TestCase):

    def setUp(self) -> None:
        self.dispatcher_shutdown = threading.Event()
        self.event_queue = EventQueue(multiprocessing.Manager().Queue())
        self.dispatcher = EventDispatcher(
            shutdown=self.dispatcher_shutdown,
            event_queue=self.event_queue,
        )

    def tearDown(self) -> None:
        self.dispatcher_shutdown.set()

    def test_empties_queue(self) -> None:
        self.event_queue.publish(
            request_id='1234',
            event_name=eventNames.WORK_STARTED,
            event_payload={'hello': 'events'},
            publisher_id=self.__class__.__name__,
        )
        self.dispatcher.run_once()
        with self.assertRaises(queue.Empty):
            self.dispatcher.run_once()

    @mock.patch('time.time')
    def subscribe(self, mock_time: mock.Mock) -> DictQueueType:
        mock_time.return_value = 1234567
        q = multiprocessing.Manager().Queue()
        self.event_queue.subscribe(sub_id='1234', channel=q)
        self.dispatcher.run_once()
        self.event_queue.publish(
            request_id='1234',
            event_name=eventNames.WORK_STARTED,
            event_payload={'hello': 'events'},
            publisher_id=self.__class__.__name__,
        )
        self.dispatcher.run_once()
        self.assertEqual(
            q.get(), {
                'request_id': '1234',
                'process_id': os.getpid(),
                'thread_id': threading.get_ident(),
                'event_timestamp': 1234567,
                'event_name': eventNames.WORK_STARTED,
                'event_payload': {'hello': 'events'},
                'publisher_id': self.__class__.__name__,
            },
        )
        return q

    def test_subscribe(self) -> None:
        self.subscribe()

    def test_unsubscribe(self) -> None:
        q = self.subscribe()
        self.event_queue.unsubscribe('1234')
        self.dispatcher.run_once()
        self.event_queue.publish(
            request_id='1234',
            event_name=eventNames.WORK_STARTED,
            event_payload={'hello': 'events'},
            publisher_id=self.__class__.__name__,
        )
        self.dispatcher.run_once()
        with self.assertRaises(queue.Empty):
            q.get(timeout=0.1)

    def test_unsubscribe_on_broken_pipe_error(self) -> None:
        pass

    def test_run(self) -> None:
        pass
