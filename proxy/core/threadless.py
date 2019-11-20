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
import uuid
import socket
import logging
import asyncio
import selectors
import contextlib
import multiprocessing
from multiprocessing import connection
from multiprocessing.reduction import recv_handle

from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, List, Union, Generator, Any, Type

from .event import EventQueue, eventNames

from ..common.flags import Flags
from ..common.types import HasFileno
from ..common.constants import DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


class ThreadlessWork(ABC):
    """Implement ThreadlessWork to hook into the event loop provided by Threadless process."""

    @abstractmethod
    def __init__(
            self,
            fileno: int,
            addr: Tuple[str, int],
            flags: Optional[Flags],
            event_queue: Optional[EventQueue] = None,
            uid: Optional[str] = None) -> None:
        self.fileno = fileno
        self.addr = addr
        self.flags = flags if flags else Flags()

        self.event_queue = event_queue
        self.uid: str = uid if uid is not None else uuid.uuid4().hex

    @abstractmethod
    def initialize(self) -> None:
        pass    # pragma: no cover

    @abstractmethod
    def is_inactive(self) -> bool:
        return False    # pragma: no cover

    @abstractmethod
    def get_events(self) -> Dict[socket.socket, int]:
        return {}   # pragma: no cover

    @abstractmethod
    def handle_events(
            self,
            readables: List[Union[int, HasFileno]],
            writables: List[Union[int, HasFileno]]) -> bool:
        """Return True to shutdown work."""
        return False    # pragma: no cover

    @abstractmethod
    def run(self) -> None:
        pass

    def publish_event(
            self,
            event_name: int,
            event_payload: Dict[str, Any],
            publisher_id: Optional[str] = None) -> None:
        if not self.flags.enable_events:
            return
        assert self.event_queue
        self.event_queue.publish(
            self.uid,
            event_name,
            event_payload,
            publisher_id
        )

    def shutdown(self) -> None:
        """Must close any opened resources and call super().shutdown()."""
        self.publish_event(
            event_name=eventNames.WORK_FINISHED,
            event_payload={},
            publisher_id=self.__class__.__name__
        )


class Threadless(multiprocessing.Process):
    """Threadless provides an event loop.  Use it by implementing Threadless class.

    When --threadless option is enabled, each Acceptor process also
    spawns one Threadless process.  And instead of spawning new thread
    for each accepted client connection, Acceptor process sends
    accepted client connection to Threadless process over a pipe.

    HttpProtocolHandler implements ThreadlessWork class and hooks into the
    event loop provided by Threadless.
    """

    def __init__(
            self,
            client_queue: connection.Connection,
            flags: Flags,
            work_klass: Type[ThreadlessWork],
            event_queue: Optional[EventQueue] = None) -> None:
        super().__init__()
        self.client_queue = client_queue
        self.flags = flags
        self.work_klass = work_klass
        self.event_queue = event_queue

        self.running = multiprocessing.Event()
        self.works: Dict[int, ThreadlessWork] = {}
        self.selector: Optional[selectors.DefaultSelector] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    @contextlib.contextmanager
    def selected_events(self) -> Generator[Tuple[List[Union[int, HasFileno]],
                                                 List[Union[int, HasFileno]]],
                                           None, None]:
        events: Dict[socket.socket, int] = {}
        for work in self.works.values():
            events.update(work.get_events())
        assert self.selector is not None
        for fd in events:
            self.selector.register(fd, events[fd])
        ev = self.selector.select(timeout=1)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        yield (readables, writables)
        for fd in events.keys():
            self.selector.unregister(fd)

    async def handle_events(
            self, fileno: int,
            readables: List[Union[int, HasFileno]],
            writables: List[Union[int, HasFileno]]) -> bool:
        return self.works[fileno].handle_events(readables, writables)

    # TODO: Use correct future typing annotations
    async def wait_for_tasks(
            self, tasks: Dict[int, Any]) -> None:
        for work_id in tasks:
            # TODO: Resolving one handle_events here can block resolution of
            # other tasks
            try:
                teardown = await asyncio.wait_for(tasks[work_id], DEFAULT_TIMEOUT)
                if teardown:
                    self.cleanup(work_id)
            except asyncio.TimeoutError:
                self.cleanup(work_id)

    def accept_client(self) -> None:
        addr = self.client_queue.recv()
        fileno = recv_handle(self.client_queue)
        self.works[fileno] = self.work_klass(
            fileno=fileno,
            addr=addr,
            flags=self.flags,
            event_queue=self.event_queue
        )
        self.works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__
        )
        try:
            self.works[fileno].initialize()
        except Exception as e:
            logger.exception(
                'Exception occurred during initialization',
                exc_info=e)
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
        # Invoke Threadless.handle_events
        # TODO: Only send readable / writables that client originally
        # registered.
        tasks = {}
        for fileno in self.works:
            tasks[fileno] = self.loop.create_task(
                self.handle_events(fileno, readables, writables))
        # Accepted client connection from Acceptor
        if self.client_queue in readables:
            self.accept_client()
        # Wait for Threadless.handle_events to complete
        self.loop.run_until_complete(self.wait_for_tasks(tasks))
        # Remove and shutdown inactive connections
        self.cleanup_inactive()

    def run(self) -> None:
        try:
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.client_queue, selectors.EVENT_READ)
            self.loop = asyncio.get_event_loop()
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
