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
import queue
import time
import threading
import multiprocessing
import logging
import uuid

from typing import Dict, Optional, Any, NamedTuple, List, Callable

from ..common.types import DictQueueType

logger = logging.getLogger(__name__)


EventNames = NamedTuple('EventNames', [
    ('SUBSCRIBE', int),
    ('UNSUBSCRIBE', int),
    ('WORK_STARTED', int),
    ('WORK_FINISHED', int),
    ('REQUEST_COMPLETE', int),
    ('RESPONSE_HEADERS_COMPLETE', int),
    ('RESPONSE_CHUNK_RECEIVED', int),
    ('RESPONSE_COMPLETE', int),
])
eventNames = EventNames(1, 2, 3, 4, 5, 6, 7, 8)


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

    def __init__(self) -> None:
        super().__init__()
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.Queue()

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


class EventDispatcher:
    """Core EventDispatcher.

    Provides:
    1. A dispatcher module which consumes core events and dispatches
       them to EventQueueBasePlugin
    2. A publish utility for publishing core events into
       global events queue.

    Direct consuming from global events queue outside of dispatcher
    module is not-recommended.  Python native multiprocessing queue
    doesn't provide a fanout functionality which core dispatcher module
    implements so that several plugins can consume same published
    event at a time.

    When --enable-events is used, a multiprocessing.Queue is created and
    attached to global Flags.  This queue can then be used for
    dispatching an Event dict object into the queue.

    When --enable-events is used, dispatcher module is automatically
    started. Dispatcher module also ensures that queue is not full and
    doesn't utilize too much memory in case there are no event plugins
    enabled.
    """

    def __init__(
            self,
            shutdown: threading.Event,
            event_queue: EventQueue) -> None:
        self.shutdown: threading.Event = shutdown
        self.event_queue: EventQueue = event_queue
        self.subscribers: Dict[str, DictQueueType] = {}

    def handle_event(self, ev: Dict[str, Any]) -> None:
        if ev['event_name'] == eventNames.SUBSCRIBE:
            self.subscribers[ev['event_payload']['sub_id']] = \
                ev['event_payload']['channel']
        elif ev['event_name'] == eventNames.UNSUBSCRIBE:
            del self.subscribers[ev['event_payload']['sub_id']]
        else:
            # logger.info(ev)
            unsub_ids: List[str] = []
            for sub_id in self.subscribers:
                try:
                    self.subscribers[sub_id].put(ev)
                except BrokenPipeError:
                    unsub_ids.append(sub_id)
            for sub_id in unsub_ids:
                del self.subscribers[sub_id]

    def run_once(self) -> None:
        ev: Dict[str, Any] = self.event_queue.queue.get(timeout=1)
        self.handle_event(ev)

    def run(self) -> None:
        try:
            while not self.shutdown.is_set():
                try:
                    self.run_once()
                except queue.Empty:
                    pass
        except EOFError:
            pass
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Event dispatcher exception', exc_info=e)


class EventSubscriber:
    """Core event subscriber."""

    def __init__(self, event_queue: EventQueue) -> None:
        self.manager = multiprocessing.Manager()
        self.event_queue = event_queue
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_channel: Optional[DictQueueType] = None
        self.relay_sub_id: Optional[str] = None

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        self.relay_shutdown = threading.Event()
        self.relay_channel = self.manager.Queue()
        self.relay_thread = threading.Thread(
            target=self.relay,
            args=(self.relay_shutdown, self.relay_channel, callback))
        self.relay_thread.start()
        self.relay_sub_id = uuid.uuid4().hex
        self.event_queue.subscribe(self.relay_sub_id, self.relay_channel)
        logger.debug(
            'Subscribed relay sub id %s from core events',
            self.relay_sub_id)

    def unsubscribe(self) -> None:
        if self.relay_sub_id is None:
            logger.warning('Unsubscribe called without existing subscription')
            return

        assert self.relay_thread
        assert self.relay_shutdown
        assert self.relay_channel
        assert self.relay_sub_id

        self.event_queue.unsubscribe(self.relay_sub_id)
        self.relay_shutdown.set()
        self.relay_thread.join()
        logger.debug(
            'Un-subscribed relay sub id %s from core events',
            self.relay_sub_id)

        self.relay_thread = None
        self.relay_shutdown = None
        self.relay_channel = None
        self.relay_sub_id = None

    @staticmethod
    def relay(
            shutdown: threading.Event,
            channel: DictQueueType,
            callback: Callable[[Dict[str, Any]], None]) -> None:
        while not shutdown.is_set():
            try:
                ev = channel.get(timeout=1)
                callback(ev)
            except queue.Empty:
                pass
            except EOFError:
                break
            except KeyboardInterrupt:
                break
