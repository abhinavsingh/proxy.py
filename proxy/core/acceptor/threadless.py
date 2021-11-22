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

from abc import abstractmethod, ABC
from typing import Dict, Optional, Tuple, List, Set, Generic, TypeVar

from .work import Work

from ..event import EventQueue

from ...common.logger import Logger
from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_SELECTOR_SELECT_TIMEOUT

T = TypeVar("T")

logger = logging.getLogger(__name__)


class Threadless(ABC, Generic[T]):
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
            work_queue: T,
            flags: argparse.Namespace,
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        self.work_queue = work_queue
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
        self.wait_timeout: float = (
            self.flags.num_workers / 2) * DEFAULT_SELECTOR_SELECT_TIMEOUT

    @abstractmethod
    def receive_from_work_queue(self) -> None:
        """Work queue is ready to receive new work."""
        raise NotImplementedError()

    @abstractmethod
    def work_queue_fileno(self) -> Optional[int]:
        """If work queue must be selected before calling
        ``receive_from_work_queue`` then implementation must
        return work queue fd."""
        raise NotImplementedError()

    @abstractmethod
    def close_work_queue(self) -> None:
        """If an fd was selectable for work queue, make sure
        to close the work queue fd here."""
        raise NotImplementedError()

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
        new_work_available = False
        wqfileno = self.work_queue_fileno()
        if wqfileno is None:
            new_work_available = True
        for key, mask in selected:
            if wqfileno is not None and key.fileobj == wqfileno:
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

    async def _wait_for_tasks(
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
                self._cleanup(task._work_id)     # type: ignore
                # self.cleanup(int(task.get_name()))

    def _fromfd(self, fileno: int) -> socket.socket:
        return socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )

    # TODO: Use cached property to avoid execution repeatedly
    # within a second interval.  Note that our selector timeout
    # is 0.1 second which can unnecessarily result in cleanup
    # checks within a second boundary.
    def _cleanup_inactive(self) -> None:
        inactive_works: List[int] = []
        for work_id in self.works:
            if self.works[work_id].is_inactive():
                inactive_works.append(work_id)
        for work_id in inactive_works:
            self._cleanup(work_id)

    # TODO: HttpProtocolHandler.shutdown can call flush which may block
    def _cleanup(self, work_id: int) -> None:
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

    async def _run_once(self) -> None:
        assert self.loop is not None
        work_fds, work_by_ids, new_work_available = await self._selected_events()
        try:
            # Accept new work if available
            #
            # TODO: We must use a work klass to handle
            # client_queue fd itself a.k.a. accept_client
            # will become handle_readables.
            if new_work_available:
                self.receive_from_work_queue()
            if len(work_by_ids) == 0:
                self._cleanup_inactive()
                return
        finally:
            assert self.selector
            for wfd in work_fds:
                self.selector.unregister(wfd)
        # Invoke Threadless.handle_events
        self.unfinished.update(self._create_tasks(work_by_ids))
        logger.debug('Executing {0} works'.format(len(self.unfinished)))
        await self._wait_for_tasks(self.unfinished)
        logger.debug(
            'Done executing works, {0} pending'.format(
                len(self.unfinished),
            ),
        )
        # Remove and shutdown inactive workers
        self._cleanup_inactive()

    def run(self) -> None:
        Logger.setup(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        wqfileno = self.work_queue_fileno()
        try:
            self.selector = selectors.DefaultSelector()
            if wqfileno is not None:
                self.selector.register(
                    wqfileno,
                    selectors.EVENT_READ,
                    data=wqfileno,
                )
            self.loop = asyncio.get_event_loop_policy().get_event_loop()
            while not self.running.is_set():
                # logger.debug('Working on {0} works'.format(len(self.works)))
                self.loop.run_until_complete(self._run_once())
        except KeyboardInterrupt:
            pass
        finally:
            assert self.selector is not None
            if wqfileno is not None:
                self.selector.unregister(wqfileno)
                self.close_work_queue()
            assert self.loop is not None
            self.loop.close()
