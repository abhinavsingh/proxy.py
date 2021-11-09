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
import selectors
import threading
import multiprocessing
import multiprocessing.synchronize
from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle

from typing import List, Optional, Tuple, Type

from .work import Work

from ..connection import TcpClientConnection
from ..event import EventQueue, eventNames

from ...common.utils import is_threadless
from ...common.logger import Logger

logger = logging.getLogger(__name__)


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
            executor_queues: List[connection.Connection],
            executor_pids: List[int],
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
        self.executor_queues = executor_queues
        self.executor_pids = executor_pids
        # Selector
        self.running = multiprocessing.Event()
        self.selector: Optional[selectors.DefaultSelector] = None
        # File descriptor used to accept new work
        # Currently, a socket fd is assumed.
        self.sock: Optional[socket.socket] = None
        # Incremented every time work() is called
        self._total: int = 0

    def run_once(self) -> None:
        with self.lock:
            assert self.selector and self.sock
            events = self.selector.select(timeout=1)
            if len(events) == 0:
                return
            conn, addr = self.sock.accept()
        addr = None if addr == '' else addr
        self._work(conn, addr)

    def run(self) -> None:
        Logger.setup_logger(
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
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.selector.unregister(self.sock)
            self.sock.close()
            logger.debug('Acceptor#%d shutdown', self.idd)

    def _work(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        if is_threadless(self.flags.threadless, self.flags.threaded):
            self._start_threadless_work(conn, addr)
        else:
            self._start_threaded_work(conn, addr)
        self._total += 1

    def _start_threadless_work(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        # Index of worker to which this work should be dispatched
        # Use round-robin strategy by default.
        #
        # By default all acceptors will start sending work to
        # 1st workers.  To randomize, we offset index by idd.
        index = (self._total + self.idd) % self.flags.num_workers
        # Accepted client address is empty string for
        # unix socket domain, avoid sending empty string
        if not self.flags.unix_socket_path:
            self.executor_queues[index].send(addr)
        send_handle(
            self.executor_queues[index],
            conn.fileno(),
            self.executor_pids[index],
        )
        conn.close()
        logger.debug(
            'Dispatched work#{0} from acceptor#{1} to worker#{2}'.format(
                self._total, self.idd, index,
            ),
        )

    def _start_threaded_work(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        work = self.work_klass(
            TcpClientConnection(conn, addr),
            flags=self.flags,
            event_queue=self.event_queue,
        )
        # TODO: Keep reference to threads and join during shutdown.
        # This will ensure connections are not abruptly closed on shutdown.
        work_thread = threading.Thread(target=work.run)
        work_thread.daemon = True
        work_thread.start()
        work.publish_event(
            event_name=eventNames.WORK_STARTED,
            event_payload={'fileno': conn.fileno(), 'addr': addr},
            publisher_id=self.__class__.__name__,
        )
        logger.debug(
            'Started work#{0} in thread#{1}'.format(
                self._total, work_thread.ident,
            ),
        )
