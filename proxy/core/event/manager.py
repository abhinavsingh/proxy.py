# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
import threading
import multiprocessing

from typing import Optional

from .queue import EventQueue
from .dispatcher import EventDispatcher

from ...common.flag import flags
from ...common.constants import DEFAULT_ENABLE_EVENTS

logger = logging.getLogger(__name__)


flags.add_argument(
    '--enable-events',
    action='store_true',
    default=DEFAULT_ENABLE_EVENTS,
    help='Default: False.  Enables core to dispatch lifecycle events. '
    'Plugins can be used to subscribe for core events.',
)


class EventManager:
    """Event manager is an encapsulation around various initialization, dispatcher
    start / stop API required for end-to-end eventing.
    """

    def __init__(self) -> None:
        self.event_queue: Optional[EventQueue] = None
        self.event_dispatcher: Optional[EventDispatcher] = None
        self.event_dispatcher_thread: Optional[threading.Thread] = None
        self.event_dispatcher_shutdown: Optional[threading.Event] = None
        self.manager: Optional[multiprocessing.managers.SyncManager] = None

    def start_event_dispatcher(self) -> None:
        self.manager = multiprocessing.Manager()
        self.event_queue = EventQueue(self.manager.Queue())
        self.event_dispatcher_shutdown = threading.Event()
        assert self.event_dispatcher_shutdown
        assert self.event_queue
        self.event_dispatcher = EventDispatcher(
            shutdown=self.event_dispatcher_shutdown,
            event_queue=self.event_queue,
        )
        self.event_dispatcher_thread = threading.Thread(
            target=self.event_dispatcher.run,
        )
        self.event_dispatcher_thread.start()
        logger.debug('Thread ID: %d', self.event_dispatcher_thread.ident)

    def stop_event_dispatcher(self) -> None:
        assert self.event_dispatcher_shutdown
        assert self.event_dispatcher_thread
        self.event_dispatcher_shutdown.set()
        self.event_dispatcher_thread.join()
        logger.debug(
            'Shutdown of global event dispatcher thread %d successful',
            self.event_dispatcher_thread.ident,
        )
