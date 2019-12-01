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
import unittest
from typing import Dict, Any

from unittest import mock

from proxy.core.event import EventQueue, EventDispatcher, EventSubscriber, eventNames

PUBLISHER_ID = threading.get_ident()


class TestEventSubscriber(unittest.TestCase):

    @mock.patch('time.time')
    def test_event_subscriber(self, mock_time: mock.Mock) -> None:
        mock_time.return_value = 1234567
        self.dispatcher_shutdown = threading.Event()
        self.event_queue = EventQueue()
        self.dispatcher = EventDispatcher(
            shutdown=self.dispatcher_shutdown,
            event_queue=self.event_queue)
        self.subscriber = EventSubscriber(self.event_queue)

        self.subscriber.subscribe(self.callback)
        self.dispatcher.run_once()

        self.event_queue.publish(
            request_id='1234',
            event_name=eventNames.WORK_STARTED,
            event_payload={'hello': 'events'},
            publisher_id=self.__class__.__name__
        )
        self.dispatcher.run_once()

        self.subscriber.unsubscribe()
        self.dispatcher.run_once()
        self.dispatcher_shutdown.set()

    def callback(self, ev: Dict[str, Any]) -> None:
        self.assertEqual(ev, {
            'request_id': '1234',
            'process_id': os.getpid(),
            'thread_id': PUBLISHER_ID,
            'event_timestamp': 1234567,
            'event_name': eventNames.WORK_STARTED,
            'event_payload': {'hello': 'events'},
            'publisher_id': self.__class__.__name__,
        })
