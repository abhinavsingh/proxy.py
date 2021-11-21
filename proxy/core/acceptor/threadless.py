# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       acceptor
"""
import os
import socket
import logging
import asyncio
import argparse
import selectors
import multiprocessing

from multiprocessing import connection
from multiprocessing.reduction import recv_handle
from typing import Dict, Optional, Tuple, List, Set

from .work import Work

from ..connection import TcpClientConnection
from ..event import EventQueue, eventNames

from ...common.logger import Logger
from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_SELECTOR_SELECT_TIMEOUT

logger = logging.getLogger(__name__)


class Threadless:
    """Work executor process.

    Threadless process provides an event loop, which is shared across
    multiple :class:`~proxy.core.acceptor.work.Work` instances to handle
    work.

    Threadless takes input a `work_klass` and an `event_queue`.  `work_klass`
    must conform to the :class:`~proxy.core.acceptor.work.Work`
    protocol.  Work is received over the `event_queue`.

    When a work is accepted, threadless creates a new instance of `work_klass`.
    Threadless will then invoke necessary lifecycle of the
    :class:`~proxy.core.acceptor.work.Work` protocol,
    allowing `work_klass` implementation to handle the assigned work.

    Example, :class:`~proxy.core.base.tcp_server.BaseTcpServerHandler`
    implements :class:`~proxy.core.acceptor.work.Work` protocol. It
    expects a client connection as work payload and hooks into the
    threadless event loop to handle the client connection.
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
        # If we remove single quotes for typing hint below,
        # runtime exceptions will occur for < Python 3.9.
        #
        # Ref https://github.com/abhinavsingh/proxy.py/runs/4279055360?check_suite_focus=true
        self.unfinished: Set['asyncio.Task[bool]'] = set()
        self.wait_timeout: float = (self.flags.num_workers / 2) * DEFAULT_SELECTOR_SELECT_TIMEOUT

    async def _selected_events(self) -> Tuple[
            List[socket.socket],
            Dict[int, Tuple[Readables, Writables]],
            bool,
    ]:
        """For each work, collects events they are interested in.
        Calls select for events of interest.  """
        assert self.selector is not None
        work_fds: List[socket.socket] = []
        for work_id in self.works:
            worker_events = await self.works[work_id].get_events()
            for fd in worker_events:
                # Can throw ValueError: Invalid file descriptor: -1
                #
                # A guard within Work classes may not help here due to
                # asynchronous nature.  Hence, threadless will handle
                # ValueError exceptions raised by selector.register
                # for invalid fd.
                self.selector.register(
                    fd, events=worker_events[fd],
                    data=work_id,
                )
                work_fds.append(fd)
        selected = self.selector.select(
            timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT,
        )
        # Keys are work_id and values are 2-tuple indicating
        # readables & writables that work_id is interested in
        # and are ready for IO.
        work_by_ids: Dict[int, Tuple[Readables, Writables]] = {}
        client_queue_fileno = self.client_queue.fileno()
        new_work_available = False
        for key, mask in selected:
            if key.fileobj == client_queue_fileno:
                assert mask & selectors.EVENT_READ
                new_work_available = True
                continue
            if key.data not in work_by_ids:
                work_by_ids[key.data] = ([], [])
            if mask & selectors.EVENT_READ:
                work_by_ids[key.data][0].append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                work_by_ids[key.data][1].append(key.fileobj)
        return (work_fds, work_by_ids, new_work_available)

    async def wait_for_tasks(
            self,
            pending: Set['asyncio.Task[bool]'],
    ) -> None:
        finished, self.unfinished = await asyncio.wait(
            pending,
            timeout=self.wait_timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in finished:
            if task.result():
                self.cleanup(task._work_id)     # type: ignore
                # self.cleanup(int(task.get_name()))

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

    # TODO: Use cached property to avoid execution repeatedly
    # within a second interval.  Note that our selector timeout
    # is 0.1 second which can unnecessarily result in cleanup
    # checks within a second boundary.
    def cleanup_inactive(self) -> None:
        inactive_works: List[int] = []
        for work_id in self.works:
            if self.works[work_id].is_inactive():
                inactive_works.append(work_id)
        for work_id in inactive_works:
            self.cleanup(work_id)

    # TODO: HttpProtocolHandler.shutdown can call flush which may block
    def cleanup(self, work_id: int) -> None:
        self.works[work_id].shutdown()
        del self.works[work_id]
        os.close(work_id)

    def _create_tasks(
            self,
            work_by_ids: Dict[int, Tuple[Readables, Writables]],
    ) -> Set['asyncio.Task[bool]']:
        assert self.loop
        tasks: Set['asyncio.Task[bool]'] = set()
        for work_id in work_by_ids:
            task = self.loop.create_task(
                self.works[work_id].handle_events(*work_by_ids[work_id]),
            )
            task._work_id = work_id     # type: ignore
            # task.set_name(work_id)
            tasks.add(task)
        return tasks

    async def run_once(self) -> None:
        assert self.loop is not None
        work_fds, work_by_ids, new_work_available = await self._selected_events()
        try:
            # Accept new work if available
            #
            # TODO: We must use a work klass to handle
            # client_queue fd itself a.k.a. accept_client
            # will become handle_readables.
            if new_work_available:
                self.accept_client()
            if len(work_by_ids) == 0:
                self.cleanup_inactive()
                return
        finally:
            assert self.selector
            for wfd in work_fds:
                self.selector.unregister(wfd)
        # Invoke Threadless.handle_events
        self.unfinished.update(self._create_tasks(work_by_ids))
        logger.debug('Executing {0} works'.format(len(self.unfinished)))
        await self.wait_for_tasks(self.unfinished)
        logger.debug(
            'Done executing works, {0} pending'.format(
                len(self.unfinished),
            ),
        )
        # Remove and shutdown inactive workers
        self.cleanup_inactive()

    def run(self) -> None:
        Logger.setup(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(
                self.client_queue.fileno(),
                selectors.EVENT_READ,
                data=self.client_queue.fileno(),
            )
            self.loop = asyncio.get_event_loop_policy().get_event_loop()
            while not self.running.is_set():
                # logger.debug('Working on {0} works'.format(len(self.works)))
                self.loop.run_until_complete(self.run_once())
        except KeyboardInterrupt:
            pass
        finally:
            assert self.selector is not None
            self.selector.unregister(self.client_queue.fileno())
            self.client_queue.close()
            assert self.loop is not None
            self.loop.close()
