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

from typing import Optional, Type
from types import TracebackType

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
    """Event manager is a context manager which provides
    encapsulation around various setup and shutdown steps
    to start the eventing core.
    """

    def __init__(self) -> None:
        self.queue: Optional[EventQueue] = None
        self.dispatcher: Optional[EventDispatcher] = None
        self.dispatcher_thread: Optional[threading.Thread] = None
        self.dispatcher_shutdown: Optional[threading.Event] = None
        self.manager: Optional[multiprocessing.managers.SyncManager] = None

    def __enter__(self) -> 'EventManager':
        self.setup()
        return self

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
    ) -> None:
        self.shutdown()

    def setup(self) -> None:
        self.manager = multiprocessing.Manager()
        self.queue = EventQueue(self.manager.Queue())
        self.dispatcher_shutdown = threading.Event()
        assert self.dispatcher_shutdown
        assert self.queue
        self.dispatcher = EventDispatcher(
            shutdown=self.dispatcher_shutdown,
            event_queue=self.queue,
        )
        self.dispatcher_thread = threading.Thread(
            target=self.dispatcher.run,
        )
        self.dispatcher_thread.start()
        logger.debug('Thread ID: %d', self.dispatcher_thread.ident)

    def shutdown(self) -> None:
        assert self.dispatcher_shutdown and self.dispatcher_thread and self.manager
        self.dispatcher_shutdown.set()
        self.dispatcher_thread.join()
        self.manager.shutdown()
        logger.debug(
            'Shutdown of global event dispatcher thread %d successful',
            self.dispatcher_thread.ident,
        )
