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
import os
import socket
import logging
import asyncio
import selectors
import contextlib
import multiprocessing

from multiprocessing import connection
from multiprocessing.reduction import recv_handle
from typing import Dict, Optional, Tuple, List, Generator, Any

from .work import Work

from ..connection import TcpClientConnection
from ..event import EventQueue, eventNames

from ...common.logger import Logger
from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


class Threadless(multiprocessing.Process):
    """Work executor process.

    Threadless process provides an event loop, which is shared across
    multiple `Work` instances to handle work.

    Threadless takes input a `work_klass` and an `event_queue`.  `work_klass`
    must conform to the `Work` protocol.  Work is received over the
    `event_queue`.

    When a work is accepted, threadless creates a new instance of `work_klass`.
    Threadless will then invoke necessary lifecycle of the `Work` protocol,
    allowing `work_klass` implementation to handle the assigned work.

    Example, `BaseTcpServerHandler` implements `Work` protocol. It expects
    a client connection as work payload and hooks into the threadless
    event loop to handle the client connection.
    """

    def __init__(
            self,
            client_queue: connection.Connection,
            flags: argparse.Namespace,
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        self.client_queue = client_queue
        self.flags = flags
        self.event_queue = event_queue

        self.running = multiprocessing.Event()
        self.works: Dict[int, Work] = {}
        self.selector: Optional[selectors.DefaultSelector] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    @contextlib.contextmanager
    def selected_events(self) -> Generator[
        Tuple[Readables, Writables],
        None, None,
    ]:
        assert self.selector is not None
        events: Dict[socket.socket, int] = {}
        for work in self.works.values():
            worker_events = work.get_events()
            events.update(worker_events)
            for fd in worker_events:
                # Can throw ValueError: Invalid file descriptor: -1
                #
                # A guard within Work classes may not help here due to
                # asynchronous nature.  Hence, threadless will handle
                # ValueError exceptions raised by selector.register
                # for invalid fd.
                self.selector.register(fd, worker_events[fd])
        ev = self.selector.select(timeout=1)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        yield (readables, writables)
        for fd in events:
            self.selector.unregister(fd)

    async def handle_events(
            self, fileno: int,
            readables: Readables,
            writables: Writables
    ) -> bool:
        return self.works[fileno].handle_events(readables, writables)

    # TODO: Use correct future typing annotations
    async def wait_for_tasks(
            self, tasks: Dict[int, Any]
    ) -> None:
        for work_id in tasks:
            # TODO: Resolving one handle_events here can block
            # resolution of other tasks.  This can happen when handle_events
            # is slow.
            #
            # Instead of sequential await, a better option would be to await on
            # list of async handle_events.  This will allow all handlers to run
            # concurrently without blocking each other.
            try:
                teardown = await asyncio.wait_for(tasks[work_id], DEFAULT_TIMEOUT)
                if teardown:
                    self.cleanup(work_id)
            except asyncio.TimeoutError:
                self.cleanup(work_id)

    def fromfd(self, fileno: int) -> socket.socket:
        return socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )

    def accept_client(self) -> None:
        # Acceptor will not send address for
        # unix socket domain environments.
        addr = None
        if not self.flags.unix_socket_path:
            addr = self.client_queue.recv()
        fileno = recv_handle(self.client_queue)
        self.works[fileno] = self.flags.work_klass(
            TcpClientConnection(conn=self.fromfd(fileno), addr=addr),
            flags=self.flags,
            event_queue=self.event_queue,
        )
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        try:
            self.works[fileno].initialize()
        except Exception as e:
            logger.exception(
                'Exception occurred during initialization',
                exc_info=e,
            )
            self.cleanup(fileno)

    def cleanup_inactive(self) -> None:
        inactive_works: List[int] = []
        for work_id in self.works:
            if self.works[work_id].is_inactive():
                inactive_works.append(work_id)
        for work_id in inactive_works:
            self.cleanup(work_id)

    def cleanup(self, work_id: int) -> None:
        # TODO: HttpProtocolHandler.shutdown can call flush which may block
        self.works[work_id].shutdown()
        del self.works[work_id]
        os.close(work_id)

    def run_once(self) -> None:
        assert self.loop is not None
        with self.selected_events() as (readables, writables):
            if len(readables) == 0 and len(writables) == 0:
                # Remove and shutdown inactive connections
                self.cleanup_inactive()
                return
        # Note that selector from now on is idle,
        # until all the logic below completes.
        #
        # This is where one process per CPU architecture shines,
        # as other threadless processes can continue process work
        # within their context.
        #
        # Invoke Threadless.handle_events
        #
        # TODO: Only send readable / writables that client originally
        # registered.
        tasks = {}
        for fileno in self.works:
            tasks[fileno] = self.loop.create_task(
                self.handle_events(fileno, readables, writables),
            )
        # Accepted client connection from Acceptor
        if self.client_queue in readables:
            self.accept_client()
        # Wait for Threadless.handle_events to complete
        self.loop.run_until_complete(self.wait_for_tasks(tasks))
        # Remove and shutdown inactive workers
        self.cleanup_inactive()

    def run(self) -> None:
        Logger.setup_logger(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.client_queue, selectors.EVENT_READ)
            self.loop = asyncio.get_event_loop_policy().get_event_loop()
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            assert self.selector is not None
            self.selector.unregister(self.client_queue)
            self.client_queue.close()
            assert self.loop is not None
            self.loop.close()
