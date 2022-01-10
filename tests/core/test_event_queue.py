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
import threading
import multiprocessing

import unittest
from unittest import mock

from proxy.core.event import EventQueue, eventNames


class TestCoreEvent(unittest.TestCase):

    def setUp(self) -> None:
        self.manager = multiprocessing.Manager()

    def tearDown(self) -> None:
        self.manager.shutdown()

    @mock.patch('time.time')
    def test_publish(self, mock_time: mock.Mock) -> None:
        mock_time.return_value = 1234567
        evq = EventQueue(self.manager.Queue())
        evq.publish(
            request_id='1234',
            event_name=eventNames.WORK_STARTED,
            event_payload={'hello': 'events'},
            publisher_id=self.__class__.__name__,
        )
        self.assertEqual(
            evq.queue.get(), {
                'request_id': '1234',
                'process_id': os.getpid(),
                'thread_id': threading.get_ident(),
                'event_timestamp': 1234567,
                'event_name': eventNames.WORK_STARTED,
                'event_payload': {'hello': 'events'},
                'publisher_id': self.__class__.__name__,
            },
        )

    def test_subscribe(self) -> None:
        evq = EventQueue(self.manager.Queue())
        _, relay_send = multiprocessing.Pipe()
        print(relay_send)
        evq.subscribe('1234', relay_send)
        ev = evq.queue.get()
        self.assertEqual(ev['event_name'], eventNames.SUBSCRIBE)
        self.assertEqual(ev['event_payload']['sub_id'], '1234')
        # Not the same as the one sent over multiprocessing.Queue
        # will be another descriptor.  We must ideally use
        # send_handle during subscription too.
        #
        # self.assertEqual(ev['event_payload']
        #                  ['conn'].fileno(), relay_send.fileno())

    def test_unsubscribe(self) -> None:
        evq = EventQueue(self.manager.Queue())
        evq.unsubscribe('1234')
        ev = evq.queue.get()
        self.assertEqual(ev['event_name'], eventNames.UNSUBSCRIBE)
        self.assertEqual(ev['event_payload']['sub_id'], '1234')
