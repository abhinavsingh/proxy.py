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
import socket
import logging
import argparse
import selectors
import threading
import contextlib
import multiprocessing.synchronize

from multiprocessing import connection
from typing import Optional, Tuple, List, Dict, Generator, Any

from ...common.utils import is_threadless
from ...common.types import Readables, Writables
from ...common.constants import DEFAULT_SELECTOR_SELECT_TIMEOUT

from ..event import EventQueue, eventNames
from ..connection import TcpClientConnection

from .executors import ThreadlessPool
from .work import Work

logger = logging.getLogger(__name__)


class LocalExecutor(threading.Thread):
    """Listens for READ_EVENT over a queue, accepts and initializes work."""

    def __init__(
            self,
            idd: int,
            flags: argparse.Namespace,
            sock: socket.socket,
            evq: queue.Queue[Any],
            executor_queues: List[connection.Connection],
            executor_pids: List[int],
            executor_locks: List[multiprocessing.synchronize.Lock],
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        # Index assigned by `AcceptorPool`
        self.idd = idd
        self.sock = sock
        self.evq = evq
        self.flags = flags
        self.executor_queues = executor_queues
        self.executor_pids = executor_pids
        self.executor_locks = executor_locks
        self.event_queue = event_queue
        # Incremented every time work() is called
        self._total: int = 0
        self._selector: Optional[selectors.DefaultSelector] = None
        self._works: Dict[int, Work] = {}

    @contextlib.contextmanager
    def selected_events(self) -> Generator[
        Tuple[Readables, Writables],
        None, None,
    ]:
        assert self._selector is not None
        events: Dict[socket.socket, int] = {}
        for work in self._works.values():
            worker_events = work.get_events()
            events.update(worker_events)
            for fd in worker_events:
                # Can throw ValueError: Invalid file descriptor: -1
                #
                # A guard within Work classes may not help here due to
                # asynchronous nature.  Hence, threadless will handle
                # ValueError exceptions raised by selector.register
                # for invalid fd.
                self._selector.register(fd, worker_events[fd])
        ev = self._selector.select(timeout=DEFAULT_SELECTOR_SELECT_TIMEOUT)
        readables = []
        writables = []
        for key, mask in ev:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)
        yield (readables, writables)
        for fd in events:
            self._selector.unregister(fd)

    def run_once(self) -> bool:
        try:
            payload = self.evq.get(block=True, timeout=0.1)
            if isinstance(payload, bool) and payload is False:
                return True
            assert isinstance(payload, tuple)
            conn, addr = payload
            addr = None if addr == '' else addr
            self.dispatch(conn, addr)
        except queue.Empty:
            pass
        return False

    def run(self) -> None:
        self._selector = selectors.DefaultSelector()
        try:
            while 1:
                if self.run_once():
                    break
        except KeyboardInterrupt:
            pass

    def work(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        fileno = conn.fileno()
        self._works[fileno] = self.flags.work_klass(
            TcpClientConnection(conn=conn, addr=addr),
            flags=self.flags,
            event_queue=self.event_queue,
        )
        self._works[fileno].publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': fileno, 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        try:
            self._works[fileno].initialize()
        except Exception as e:
            logger.exception(
                'Exception occurred during initialization',
                exc_info=e,
            )
            self._cleanup(fileno)

    def _cleanup(self, work_id: int) -> None:
        # TODO: HttpProtocolHandler.shutdown can call flush which may block
        self._works[work_id].shutdown()
        del self._works[work_id]
        os.close(work_id)

    def dispatch(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        if is_threadless(self.flags.threadless, self.flags.threaded):
            # Index of worker to which this work should be dispatched
            # Use round-robin strategy by default.
            #
            # By default all acceptors will start sending work to
            # 1st workers.  To randomize, we offset index by idd.
            index = (self._total + self.idd) % self.flags.num_workers
            thread = threading.Thread(
                target=ThreadlessPool.delegate,
                args=(
                    self.executor_pids[index],
                    self.executor_queues[index],
                    self.executor_locks[index],
                    conn,
                    addr,
                    self.flags.unix_socket_path,
                ),
            )
            thread.start()
            logger.debug(
                'Dispatched work#{0}.{1} to worker#{2}'.format(
                    self.idd, self._total, index,
                ),
            )
        else:
            _, thread = ThreadlessPool.start_threaded_work(
                self.flags,
                conn, addr,
                event_queue=self.event_queue,
                publisher_id=self.__class__.__name__,
            )
            logger.debug(
                'Started work#{0}.{1} in thread#{2}'.format(
                    self.idd, self._total, thread.ident,
                ),
            )
        self._total += 1
