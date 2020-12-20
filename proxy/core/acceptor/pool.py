# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import logging
import multiprocessing
import socket
import threading
from multiprocessing import connection
from multiprocessing.reduction import send_handle
from typing import List, Optional, Type

from .acceptor import Acceptor
from .work import Work

from ..event import EventQueue, EventDispatcher
from ...common.flag import flags
from ...common.constants import DEFAULT_BACKLOG, DEFAULT_ENABLE_EVENTS
from ...common.constants import DEFAULT_IPV6_HOSTNAME, DEFAULT_NUM_WORKERS, DEFAULT_PORT

logger = logging.getLogger(__name__)

# Lock shared by worker processes
LOCK = multiprocessing.Lock()


flags.add_argument(
    '--backlog',
    type=int,
    default=DEFAULT_BACKLOG,
    help='Default: 100. Maximum number of pending connections to proxy server')

flags.add_argument(
    '--enable-events',
    action='store_true',
    default=DEFAULT_ENABLE_EVENTS,
    help='Default: False.  Enables core to dispatch lifecycle events. '
    'Plugins can be used to subscribe for core events.'
)

flags.add_argument(
    '--hostname',
    type=str,
    default=str(DEFAULT_IPV6_HOSTNAME),
    help='Default: ::1. Server IP address.')

flags.add_argument(
    '--port', type=int, default=DEFAULT_PORT,
    help='Default: 8899. Server port.')

flags.add_argument(
    '--num-workers',
    type=int,
    default=DEFAULT_NUM_WORKERS,
    help='Defaults to number of CPU cores.')


class AcceptorPool:
    """AcceptorPool.

    Pre-spawns worker processes to utilize all cores available on the system.
    A server socket is initialized and dispatched over a pipe to these workers.
    Each worker process then accepts new client connection.

    Example usage:

        pool = AcceptorPool(flags=..., work_klass=...)
        try:
            pool.setup()
            while True:
                time.sleep(1)
        finally:
            pool.shutdown()

    `work_klass` must implement `work.Work` class.

    Optionally, AcceptorPool also initialize a global event queue.
    It is a multiprocess safe queue which can be used to build pubsub patterns
    for message sharing or signaling within proxy.py.
    """

    def __init__(self, flags: argparse.Namespace,
                 work_klass: Type[Work]) -> None:
        self.flags = flags
        self.socket: Optional[socket.socket] = None
        self.acceptors: List[Acceptor] = []
        self.work_queues: List[connection.Connection] = []
        self.work_klass = work_klass

        self.event_queue: Optional[EventQueue] = None
        self.event_dispatcher: Optional[EventDispatcher] = None
        self.event_dispatcher_thread: Optional[threading.Thread] = None
        self.event_dispatcher_shutdown: Optional[threading.Event] = None
        self.manager: Optional[multiprocessing.managers.SyncManager] = None

        if self.flags.enable_events:
            self.manager = multiprocessing.Manager()
            self.event_queue = EventQueue(self.manager.Queue())

    def listen(self) -> None:
        self.socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((str(self.flags.hostname), self.flags.port))
        self.socket.listen(self.flags.backlog)
        self.socket.setblocking(False)
        logger.info(
            'Listening on %s:%d' %
            (self.flags.hostname, self.flags.port))

    def start_workers(self) -> None:
        """Start worker processes."""
        for acceptor_id in range(self.flags.num_workers):
            work_queue = multiprocessing.Pipe()
            acceptor = Acceptor(
                idd=acceptor_id,
                work_queue=work_queue[1],
                flags=self.flags,
                work_klass=self.work_klass,
                lock=LOCK,
                event_queue=self.event_queue,
            )
            acceptor.start()
            logger.debug(
                'Started acceptor#%d process %d',
                acceptor_id,
                acceptor.pid)
            self.acceptors.append(acceptor)
            self.work_queues.append(work_queue[0])
        logger.info('Started %d workers' % self.flags.num_workers)

    def start_event_dispatcher(self) -> None:
        self.event_dispatcher_shutdown = threading.Event()
        assert self.event_dispatcher_shutdown
        assert self.event_queue
        self.event_dispatcher = EventDispatcher(
            shutdown=self.event_dispatcher_shutdown,
            event_queue=self.event_queue
        )
        self.event_dispatcher_thread = threading.Thread(
            target=self.event_dispatcher.run
        )
        self.event_dispatcher_thread.start()
        logger.debug('Thread ID: %d', self.event_dispatcher_thread.ident)

    def shutdown(self) -> None:
        logger.info('Shutting down %d workers' % self.flags.num_workers)
        for acceptor in self.acceptors:
            acceptor.running.set()
        if self.flags.enable_events:
            assert self.event_dispatcher_shutdown
            assert self.event_dispatcher_thread
            self.event_dispatcher_shutdown.set()
            self.event_dispatcher_thread.join()
            logger.debug(
                'Shutdown of global event dispatcher thread %d successful',
                self.event_dispatcher_thread.ident)
        for acceptor in self.acceptors:
            acceptor.join()
        logger.debug('Acceptors shutdown')

    def setup(self) -> None:
        """Listen on port, setup workers and pass server socket to workers."""
        self.listen()
        if self.flags.enable_events:
            logger.info('Core Event enabled')
            self.start_event_dispatcher()
        self.start_workers()

        # Send server socket to all acceptor processes.
        assert self.socket is not None
        for index in range(self.flags.num_workers):
            send_handle(
                self.work_queues[index],
                self.socket.fileno(),
                self.acceptors[index].pid
            )
            self.work_queues[index].close()
        self.socket.close()
