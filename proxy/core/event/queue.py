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
import time
from typing import Dict, Optional, Any

from ...common.types import DictQueueType

from .names import eventNames


class EventQueue:
    """Global event queue.

    Each event contains:

    1. Request ID               - Globally unique
    2. Process ID               - Process ID of event publisher.
                                  This will be process id of acceptor workers.
    3. Thread ID                - Thread ID of event publisher.
                                  When --threadless is enabled, this value will
                                  be same for all the requests
                                  received by a single acceptor worker.
                                  When --threadless is disabled, this value will be
                                  Thread ID of the thread handling the client request.
    4. Event Timestamp          - Time when this event occur
    5. Event Name               - One of the defined or custom event name
    6. Event Payload            - Optional data associated with the event
    7. Publisher ID (optional)  - Optionally, publishing entity unique name / ID
    """

    def __init__(self, queue: DictQueueType) -> None:
        self.queue = queue

    def publish(
        self,
        request_id: str,
        event_name: int,
        event_payload: Dict[str, Any],
        publisher_id: Optional[str] = None
    ) -> None:
        self.queue.put({
            'request_id': request_id,
            'process_id': os.getpid(),
            'thread_id': threading.get_ident(),
            'event_timestamp': time.time(),
            'event_name': event_name,
            'event_payload': event_payload,
            'publisher_id': publisher_id,
        })

    def subscribe(
            self,
            sub_id: str,
            channel: DictQueueType) -> None:
        """Subscribe to global events."""
        self.queue.put({
            'event_name': eventNames.SUBSCRIBE,
            'event_payload': {'sub_id': sub_id, 'channel': channel},
        })

    def unsubscribe(
            self,
            sub_id: str) -> None:
        """Unsubscribe by subscriber id."""
        self.queue.put({
            'event_name': eventNames.UNSUBSCRIBE,
            'event_payload': {'sub_id': sub_id},
        })
