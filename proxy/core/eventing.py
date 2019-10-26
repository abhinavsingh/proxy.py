# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any


class EventQueueBasePlugin(ABC):

    @abstractmethod
    def handle_event(self) -> None:
        pass


class Event:
    """Defines various lifecycle events for a connection and provides
    utilities to publish events into global lifecycle events queue.

    When enabled, a multiprocessing.Queue is created and attached to
    Flags.  This queue can then be used for dispatching any event
    defined in this class or even outside of it.

    When enabled, core also assigned a unique id to each accepted client
    connection. This allows consumers to stitch several events
    together for an accepted client connection.

    Each published event contains at-least:
    1. Client ID                - Globally unique
    2. Process ID               - Process ID of event publisher
    3. Event Timestamp          - Time when this event occur
    4. Event Name               - One of the defined or custom event name
    5. Event Payload            - Optional data associated with the event
    6. Publisher ID (optional)  - Optionally, publishing entity unique name / ID
    """

    @staticmethod
    def publish(
            client_id: bytes,
            process_id: int,
            event_timestamp: float,
            event_name: bytes,
            event_payload: Dict[str, Any],
            publisher_id: Optional[bytes] = None
    ) -> None:
        pass
