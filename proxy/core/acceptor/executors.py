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
import socket
import logging
import argparse
import threading
import multiprocessing

from multiprocessing import connection
from multiprocessing.reduction import send_handle

from typing import Any, Optional, List, Tuple

from .work import Work
from .remote import RemoteExecutor

from ..connection import TcpClientConnection
from ..event import EventQueue, eventNames

from ...common.flag import flags
from ...common.utils import is_threadless
from ...common.constants import DEFAULT_NUM_WORKERS, DEFAULT_THREADLESS

logger = logging.getLogger(__name__)


flags.add_argument(
    '--threadless',
    action='store_true',
    default=DEFAULT_THREADLESS,
    help='Default: ' + ('True' if DEFAULT_THREADLESS else 'False') + '.  ' +
    'Enabled by default on Python 3.8+ (mac, linux).  ' +
    'When disabled a new thread is spawned '
    'to handle each client connection.',
)

flags.add_argument(
    '--threaded',
    action='store_true',
    default=not DEFAULT_THREADLESS,
    help='Default: ' + ('True' if not DEFAULT_THREADLESS else 'False') + '.  ' +
    'Disabled by default on Python < 3.8 and windows.  ' +
    'When enabled a new thread is spawned '
    'to handle each client connection.',
)

flags.add_argument(
    '--num-workers',
    type=int,
    default=DEFAULT_NUM_WORKERS,
    help='Defaults to number of CPU cores.',
)


class ThreadlessPool:
    """Manages lifecycle of threadless pool and delegates work to them
    using a round-robin strategy.

    Example usage::

        with ThreadlessPool(flags=...) as pool:
            while True:
                time.sleep(1)

    If necessary, start multiple threadless pool with different
    work classes.

    TODO: We could optimize multiple-work-type scenario
    by making Threadless class constructor independent of ``work_klass``.
    We could then relay the ``work_klass`` during work delegation.
    This will also make ThreadlessPool constructor agnostic
    of ``work_klass``.
    """

    def __init__(
        self,
        flags: argparse.Namespace,
        event_queue: Optional[EventQueue] = None,
    ) -> None:
        self.flags = flags
        self.event_queue = event_queue
        # Threadless worker communication states
        self.work_queues: List[connection.Connection] = []
        self.work_pids: List[int] = []
        self.work_locks: List[multiprocessing.synchronize.Lock] = []
        # List of threadless workers
        self._workers: List[RemoteExecutor] = []
        self._processes: List[multiprocessing.Process] = []

    def __enter__(self) -> 'ThreadlessPool':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    @staticmethod
    def delegate(
            worker_pid: int,
            work_queue: connection.Connection,
            work_lock: multiprocessing.synchronize.Lock,
            conn: socket.socket,
            addr: Optional[Tuple[str, int]],
            unix_socket_path: Optional[str] = None,
    ) -> None:
        """Utility method to delegate a work to threadless executor pool."""
        with work_lock:
            # Accepted client address is empty string for
            # unix socket domain, avoid sending empty string
            # for optimization.
            if not unix_socket_path:
                work_queue.send(addr)
            send_handle(
                work_queue,
                conn.fileno(),
                worker_pid,
            )
            conn.close()

    @staticmethod
    def start_threaded_work(
            flags: argparse.Namespace,
            conn: socket.socket,
            addr: Optional[Tuple[str, int]],
            event_queue: Optional[EventQueue] = None,
            publisher_id: Optional[str] = None,
    ) -> Tuple[Work, threading.Thread]:
        """Utility method to start a work in a new thread."""
        work = flags.work_klass(
            TcpClientConnection(conn, addr),
            flags=flags,
            event_queue=event_queue,
        )
        # TODO: Keep reference to threads and join during shutdown.
        # This will ensure connections are not abruptly closed on shutdown
        # for threaded execution mode.
        thread = threading.Thread(target=work.run)
        thread.daemon = True
        thread.start()
        work.publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': conn.fileno(), 'addr': addr},
            publisher_id=publisher_id or 'thread#{0}'.format(
                thread.ident,
            ),
        )
        return (work, thread)

    def setup(self) -> None:
        """Setup threadless processes."""
        if is_threadless(self.flags.threadless, self.flags.threaded):
            for index in range(self.flags.num_workers):
                self._start_worker(index)
            logger.info(
                'Started {0} threadless workers'.format(
                    self.flags.num_workers,
                ),
            )

    def shutdown(self) -> None:
        """Shutdown threadless processes."""
        if is_threadless(self.flags.threadless, self.flags.threaded):
            self._shutdown_workers()
            logger.info(
                'Stopped {0} threadless workers'.format(
                    self.flags.num_workers,
                ),
            )

    def _start_worker(self, index: int) -> None:
        """Starts a threadless worker."""
        self.work_locks.append(multiprocessing.Lock())
        pipe = multiprocessing.Pipe()
        self.work_queues.append(pipe[0])
        w = RemoteExecutor(
            work_queue=pipe[1],
            flags=self.flags,
            event_queue=self.event_queue,
        )
        self._workers.append(w)
        p = multiprocessing.Process(target=w.run)
        # p.daemon = True
        self._processes.append(p)
        p.start()
        assert p.pid
        self.work_pids.append(p.pid)
        logger.debug('Started threadless#%d process#%d', index, p.pid)

    def _shutdown_workers(self) -> None:
        """Pop a running threadless worker and clean it up."""
        for index in range(self.flags.num_workers):
            self._workers[index].running.set()
        for index in range(self.flags.num_workers):
            pid = self.work_pids[-1]
            self._processes.pop().join()
            self._workers.pop()
            self.work_pids.pop()
            self.work_queues.pop().close()
            logger.debug('Stopped threadless process#%d', pid)
        self.work_locks = []
