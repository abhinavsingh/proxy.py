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
import ssl
import socket
import logging
import asyncio
import argparse
import selectors
import multiprocessing

from abc import abstractmethod, ABC
from typing import Dict, Optional, Tuple, List, Set, Generic, TypeVar, Union

from ...common.logger import Logger
from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_INACTIVE_CONN_CLEANUP_TIMEOUT, DEFAULT_SELECTOR_SELECT_TIMEOUT
from ...common.constants import DEFAULT_WAIT_FOR_TASKS_TIMEOUT

from ..connection import TcpClientConnection
from ..event import eventNames, EventQueue

from .work import Work

T = TypeVar('T')

logger = logging.getLogger(__name__)


class Threadless(ABC, Generic[T]):
    """Work executor base class.

    Threadless provides an event loop, which is shared across
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
        # If we remove single quotes for typing hint below,
        # runtime exceptions will occur for < Python 3.9.
        #
        # Ref https://github.com/abhinavsingh/proxy.py/runs/4279055360?check_suite_focus=true
        self.unfinished: Set['asyncio.Task[bool]'] = set()
        self.registered_events_by_work_ids: Dict[
            # work_id
            int,
            # fileno, mask
            Dict[int, int],
        ] = {}
        self.wait_timeout: float = DEFAULT_WAIT_FOR_TASKS_TIMEOUT
        self.cleanup_inactive_timeout: float = DEFAULT_INACTIVE_CONN_CLEANUP_TIMEOUT

    @property
    @abstractmethod
    def loop(self) -> Optional[asyncio.AbstractEventLoop]:
        raise NotImplementedError()

    @abstractmethod
    def receive_from_work_queue(self) -> bool:
        """Work queue is ready to receive new work.

        Receive it and call ``work_on_tcp_conn``.

        Return True to tear down the loop."""
        raise NotImplementedError()

    @abstractmethod
    def work_queue_fileno(self) -> Optional[int]:
        """If work queue must be selected before calling
        ``receive_from_work_queue`` then implementation must
        return work queue fd."""
        raise NotImplementedError()

    def close_work_queue(self) -> None:
        """Only called if ``work_queue_fileno`` returns an integer.
        If an fd is select-able for work queue, make sure
        to close the work queue fd now."""
        pass    # pragma: no cover

    def work_on_tcp_conn(
            self,
            fileno: int,
            addr: Optional[Tuple[str, int]] = None,
            conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None,
    ) -> None:
        self.works[fileno] = self.flags.work_klass(
            TcpClientConnection(
                conn=conn or self._fromfd(fileno),
                addr=addr,
            ),
            flags=self.flags,
            event_queue=self.event_queue,
            uid=fileno,
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
            self._cleanup(fileno)

    async def _selected_events(self) -> Tuple[
            Dict[int, Tuple[Readables, Writables]],
            bool,
    ]:
        """For each work, collects events they are interested in.
        Calls select for events of interest.  """
        assert self.selector is not None
        unfinished_work_ids = set()
        for task in self.unfinished:
            unfinished_work_ids.add(task._work_id)   # type: ignore
        for work_id in self.works:
            if work_id in unfinished_work_ids:
                continue
            worker_events = await self.works[work_id].get_events()
            # NOTE: Current assumption is that multiple works will not
            # be interested in the same fd.  Descriptors of interests
            # returned by work must be unique.
            #
            # TODO: Ideally we must diff and unregister socks not
            # returned of interest within this _select_events call
            # but exists in registered_socks_by_work_ids
            for fileno in worker_events:
                if work_id not in self.registered_events_by_work_ids:
                    self.registered_events_by_work_ids[work_id] = {}
                mask = worker_events[fileno]
                if fileno in self.registered_events_by_work_ids[work_id]:
                    oldmask = self.registered_events_by_work_ids[work_id][fileno]
                    if mask != oldmask:
                        self.selector.modify(
                            fileno, events=mask,
                            data=work_id,
                        )
                        self.registered_events_by_work_ids[work_id][fileno] = mask
                        logger.debug(
                            'fd#{0} modified for mask#{1} by work#{2}'.format(
                                fileno, mask, work_id,
                            ),
                        )
                else:
                    # Can throw ValueError: Invalid file descriptor: -1
                    #
                    # A guard within Work classes may not help here due to
                    # asynchronous nature.  Hence, threadless will handle
                    # ValueError exceptions raised by selector.register
                    # for invalid fd.
                    self.selector.register(
                        fileno, events=mask,
                        data=work_id,
                    )
                    self.registered_events_by_work_ids[work_id][fileno] = mask
                    logger.debug(
                        'fd#{0} registered for mask#{1} by work#{2}'.format(
                            fileno, mask, work_id,
                        ),
                    )
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
        return (work_by_ids, new_work_available)

    async def _wait_for_tasks(self) -> None:
        finished, self.unfinished = await asyncio.wait(
            self.unfinished,
            timeout=self.wait_timeout,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in finished:
            if task.result():
                self._cleanup(task._work_id)    # type: ignore
                # self.cleanup(int(task.get_name()))

    def _fromfd(self, fileno: int) -> socket.socket:
        return socket.fromfd(
            fileno, family=socket.AF_INET if self.flags.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )

    def _cleanup_inactive(self) -> None:
        inactive_works: List[int] = []
        for work_id in self.works:
            if self.works[work_id].is_inactive():
                inactive_works.append(work_id)
        for work_id in inactive_works:
            self._cleanup(work_id)

    # TODO: HttpProtocolHandler.shutdown can call flush which may block
    def _cleanup(self, work_id: int) -> None:
        if work_id in self.registered_events_by_work_ids:
            assert self.selector
            for fileno in self.registered_events_by_work_ids[work_id]:
                logger.debug(
                    'fd#{0} unregistered by work#{1}'.format(
                        fileno, work_id,
                    ),
                )
                self.selector.unregister(fileno)
            self.registered_events_by_work_ids[work_id].clear()
            del self.registered_events_by_work_ids[work_id]
        self.works[work_id].shutdown()
        del self.works[work_id]
        if self.work_queue_fileno() is not None:
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
            task._work_id = work_id     # type: ignore[attr-defined]
            # task.set_name(work_id)
            tasks.add(task)
        return tasks

    async def _run_once(self) -> bool:
        assert self.loop is not None
        work_by_ids, new_work_available = await self._selected_events()
        # Accept new work if available
        #
        # TODO: We must use a work klass to handle
        # client_queue fd itself a.k.a. accept_client
        # will become handle_readables.
        if new_work_available:
            teardown = self.receive_from_work_queue()
            if teardown:
                return teardown
        if len(work_by_ids) == 0:
            return False
        # Invoke Threadless.handle_events
        self.unfinished.update(self._create_tasks(work_by_ids))
        # logger.debug('Executing {0} works'.format(len(self.unfinished)))
        await self._wait_for_tasks()
        # logger.debug(
        #     'Done executing works, {0} pending, {1} registered'.format(
        #         len(self.unfinished), len(self.registered_events_by_work_ids),
        #     ),
        # )
        return False

    async def _run_forever(self) -> None:
        tick = 0
        try:
            while True:
                if await self._run_once():
                    break
                # Check for inactive and shutdown signal only second
                if (tick * DEFAULT_SELECTOR_SELECT_TIMEOUT) > self.cleanup_inactive_timeout:
                    self._cleanup_inactive()
                    if self.running.is_set():
                        break
                    tick = 0
                tick += 1
        except KeyboardInterrupt:
            pass
        finally:
            if self.loop:
                self.loop.stop()

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
            assert self.loop
            # logger.debug('Working on {0} works'.format(len(self.works)))
            self.loop.create_task(self._run_forever())
            self.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            assert self.selector is not None
            if wqfileno is not None:
                self.selector.unregister(wqfileno)
                self.close_work_queue()
            assert self.loop is not None
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()
