# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket
import logging
import argparse
import threading
import multiprocessing

from multiprocessing import connection
from multiprocessing.reduction import send_handle

from typing import Optional, List, Tuple, Type
from types import TracebackType

from .work import Work
from .threadless import Threadless

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

    Example usage:

        with ThreadlessPool(flags=..., work_klass=...) as pool:
            while True:
                time.sleep(1)
    """

    def __init__(
        self, flags: argparse.Namespace,
        work_klass: Type[Work],
        event_queue: Optional[EventQueue] = None,
    ) -> None:
        self.flags = flags
        self.work_klass = work_klass
        self.event_queue = event_queue
        self._workers: List[Threadless] = []
        self.work_queues: List[connection.Connection] = []
        self.work_pids: List[int] = []

    def __enter__(self) -> 'ThreadlessPool':
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
        """Setup threadless processes."""
        if is_threadless(self.flags.threadless, self.flags.threaded):
            for index in range(self.flags.num_workers):
                self._start_worker(index)
            logger.debug(
                'Started {0} threadless workers'.format(
                    self.flags.num_workers,
                ),
            )

    def shutdown(self) -> None:
        """Shutdown threadless processes."""
        if is_threadless(self.flags.threadless, self.flags.threaded):
            for _ in range(self.flags.num_workers):
                self._shutdown_worker()
            logger.debug(
                'Stopped {0} threadless workers'.format(
                    self.flags.num_workers,
                ),
            )

    def _start_worker(self, index: int) -> None:
        pipe = multiprocessing.Pipe()
        self.work_queues.append(pipe[0])
        w = Threadless(
            client_queue=pipe[1],
            flags=self.flags,
            work_klass=self.work_klass,
            event_queue=self.event_queue,
        )
        self._workers.append(w)
        w.start()
        assert w.pid
        self.work_pids.append(w.pid)
        logger.debug('Started threadless#%d process#%d', index, w.pid)

    def _shutdown_worker(self) -> None:
        w = self._workers.pop()
        pid = w.pid
        w.running.set()
        w.join()
        self.work_pids.pop()
        self.work_queues.pop().close()
        logger.debug('Stopped threadless process#%d', pid)

    @staticmethod
    def start_threadless_work(
            worker_pid: int,
            work_queue: connection.Connection,
            conn: socket.socket,
            addr: Optional[Tuple[str, int]],
            unix_socket_path: Optional[str] = None,
    ) -> None:
        # Accepted client address is empty string for
        # unix socket domain, avoid sending empty string
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
            flags: argparse.ArgumentParser,
            work_klass: Type[Work],
            conn: socket.socket,
            addr: Optional[Tuple[str, int]],
            event_queue: Optional[EventQueue] = None,
            publisher_id: Optional[str] = None,
    ) -> threading.Thread:
        work = work_klass(
            TcpClientConnection(conn, addr),
            flags=flags,
            event_queue=event_queue,
        )
        # TODO: Keep reference to threads and join during shutdown.
        # This will ensure connections are not abruptly closed on shutdown.
        thread = threading.Thread(target=work.run)
        thread.daemon = True
        thread.start()
        work.publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': conn.fileno(), 'addr': addr},
            publisher_id=publisher_id or 'thread#{0}'.format(
                thread.ident),
        )
        return (work, thread)
