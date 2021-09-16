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
import multiprocessing
import socket
import threading
# import time
from multiprocessing import connection
from multiprocessing.reduction import send_handle
from typing import List, Optional, Type

from .acceptor import Acceptor
from ..threadless import ThreadlessWork
from ..event import EventQueue, EventDispatcher
from ...common.flags import Flags

logger = logging.getLogger(__name__)

LOCK = multiprocessing.Lock()

proxy_id_glob = multiprocessing.Value('i', 0)


class AcceptorPool:
    """AcceptorPool.

    Pre-spawns worker processes to utilize all cores available on the system.  Server socket connection is
    dispatched over a pipe to workers.  Each worker accepts incoming client request and spawns a
    separate thread to handle the client request.
    """

    def __init__(self, flags: Flags, work_klass: Type[ThreadlessWork]) -> None:
        self.flags = flags
        self.socket: Optional[socket.socket] = None
        self.acceptors: List[Acceptor] = []
        self.work_queues: List[connection.Connection] = []
        self.work_klass = work_klass

        # self.trx_indexer: Optional[Indexer] = None
        # self.trx_indexer_thread: Optional[threading.Thread] = None

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

    # def start_trx_indexer(self) -> None:
    #     self.trx_indexer = Indexer()
    #     self.trx_indexer_thread = threading.Thread(
    #         target=self.trx_indexer.run
    #     )
    #     self.trx_indexer_thread.start()
    #     logger.debug('Indexer thread ID: %d', self.trx_indexer_thread.ident)

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
        # self.start_trx_indexer()
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
