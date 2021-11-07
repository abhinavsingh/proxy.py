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
import multiprocessing.synchronize
import selectors
import socket
import threading

from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle
from typing import Optional, Type, Tuple

from .work import Work
from .threadless import Threadless

from ..connection import TcpClientConnection
from ..event import EventQueue, eventNames
from ...common.constants import DEFAULT_THREADLESS
from ...common.flag import flags
from ...common.utils import setup_logger

logger = logging.getLogger(__name__)


flags.add_argument(
    '--threadless',
    action='store_true',
    default=DEFAULT_THREADLESS,
    help='Default: False.  When disabled a new thread is spawned '
    'to handle each client connection.',
)


class Acceptor(multiprocessing.Process):
    """Work acceptor process.

    On start-up, `Acceptor` accepts a file descriptor which will be used to
    accept new work.  File descriptor is accepted over a `work_queue` which is
    closed immediately after receiving the descriptor.

    `Acceptor` goes on to listen for new work over the received server socket.
    By default, `Acceptor` will spawn a new thread to handle each work.

    However, when `--threadless` option is enabled, `Acceptor` process will also pre-spawns a
    `Threadless` process during start-up.  Accepted work is passed to these `Threadless` processes.
    `Acceptor` process shares accepted work with a `Threadless` process over it's dedicated pipe.

    TODO(abhinavsingh): Open questions:
    1) Instead of starting `Threadless` process, can we work with a `Threadless` thread?
    2) What are the performance implications of sharing fds between threads vs processes?
    3) How much performance degradation happens when acceptor and threadless processes are
       running on separate CPU cores?
    4) Can we ensure both acceptor and threadless process are pinned to the same CPU core?
    """

    def __init__(
            self,
            idd: int,
            work_queue: connection.Connection,
            flags: argparse.Namespace,
            work_klass: Type[Work],
            lock: multiprocessing.synchronize.Lock,
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        self.flags = flags
        # Eventing core queue
        self.event_queue = event_queue
        # Index assigned by `AcceptorPool`
        self.idd = idd
        # Lock shared by all acceptor processes
        # to avoid concurrent accept over server socket
        self.lock = lock
        # Queue over which server socket fd is received on start-up
        self.work_queue: connection.Connection = work_queue
        # Worker class
        self.work_klass = work_klass
        # Selector & threadless states
        self.running = multiprocessing.Event()
        self.selector: Optional[selectors.DefaultSelector] = None
        self.threadless_process: Optional[Threadless] = None
        self.threadless_client_queue: Optional[connection.Connection] = None
        # File descriptor used to accept new work
        # Currently, a socket fd is assumed.
        self.sock: Optional[socket.socket] = None

    def start_threadless_process(self) -> None:
        pipe = multiprocessing.Pipe()
        self.threadless_client_queue = pipe[0]
        self.threadless_process = Threadless(
            client_queue=pipe[1],
            flags=self.flags,
            work_klass=self.work_klass,
            event_queue=self.event_queue,
        )
        self.threadless_process.start()
        logger.debug('Started process %d', self.threadless_process.pid)

    def shutdown_threadless_process(self) -> None:
        assert self.threadless_process and self.threadless_client_queue
        logger.debug('Stopped process %d', self.threadless_process.pid)
        self.threadless_process.running.set()
        self.threadless_process.join()
        self.threadless_client_queue.close()

    def _start_threadless_work(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        assert self.threadless_process and self.threadless_client_queue
        self.threadless_client_queue.send(addr)
        send_handle(
            self.threadless_client_queue,
            conn.fileno(),
            self.threadless_process.pid,
        )
        conn.close()

    def _start_threaded_work(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        work = self.work_klass(
            TcpClientConnection(conn, addr),
            flags=self.flags,
            event_queue=self.event_queue,
        )
        work_thread = threading.Thread(target=work.run)
        work_thread.daemon = True
        work.publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': conn.fileno(), 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        work_thread.start()

    def run_once(self) -> None:
        with self.lock:
            assert self.selector and self.sock
            events = self.selector.select(timeout=1)
            if len(events) == 0:
                return
            conn, addr = self.sock.accept()
        if (
                self.flags.threadless and
                self.threadless_client_queue and
                self.threadless_process
        ):
            self._start_threadless_work(conn, addr)
        else:
            self._start_threaded_work(conn, addr)

    def run(self) -> None:
        setup_logger(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        self.selector = selectors.DefaultSelector()
        fileno = recv_handle(self.work_queue)
        self.work_queue.close()
        self.sock = socket.fromfd(
            fileno,
            family=self.flags.family,
            type=socket.SOCK_STREAM,
        )
        try:
            self.selector.register(self.sock, selectors.EVENT_READ)
            if self.flags.threadless:
                self.start_threadless_process()
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.selector.unregister(self.sock)
            if self.flags.threadless:
                self.shutdown_threadless_process()
            self.sock.close()
            logger.debug('Acceptor#%d shutdown', self.idd)
