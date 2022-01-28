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
import time
import threading
from typing import Any, Dict, Optional
from multiprocessing import connection

from .names import eventNames
from ...common.types import DictQueueType


class EventQueue:
    """Global event queue.  Must be a multiprocess safe queue capable of
    transporting other queues.  This is necessary because currently
    subscribers use a separate subscription queue to consume events.
    Subscription queue is exchanged over the global event queue.

    Each published event contains following schema::

        {
            'request_id': 'Globally unique request ID',
            'process_id': 'Process ID of event publisher. This '
                          'will be the process ID of acceptor workers.',
            'thread_id': 'Thread ID of event publisher. '
                         'When --threadless is enabled, this value '
                         'will be same for all the requests.'
            'event_timestamp': 'Time when this event occured',
            'event_name': 'one of the pre-defined or custom event name',
            'event_payload': 'Optional data associated with the event',
            'publisher_id': 'Optional publisher entity unique name',
        }

    """

    def __init__(self, queue: DictQueueType) -> None:
        self.queue = queue

    def publish(
        self,
        request_id: str,
        event_name: int,
        event_payload: Dict[str, Any],
        publisher_id: Optional[str] = None,
    ) -> None:
        self.queue.put_nowait({
            'process_id': os.getpid(),
            'thread_id': threading.get_ident(),
            'event_timestamp': time.time(),
            'request_id': request_id,
            'event_name': event_name,
            'event_payload': event_payload,
            'publisher_id': publisher_id,
        })

    def subscribe(
            self,
            sub_id: str,
            channel: connection.Connection,
    ) -> None:
        """Subscribe to global events.

        sub_id is a subscription identifier which must be globally
        unique.  channel MUST be a multiprocessing connection.
        """
        self.queue.put_nowait({
            'event_name': eventNames.SUBSCRIBE,
            'event_payload': {'sub_id': sub_id, 'conn': channel},
        })

    def unsubscribe(
            self,
            sub_id: str,
    ) -> None:
        """Unsubscribe by subscriber id."""
        self.queue.put_nowait({
            'event_name': eventNames.UNSUBSCRIBE,
            'event_payload': {'sub_id': sub_id},
        })
