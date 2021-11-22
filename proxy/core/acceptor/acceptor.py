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
       pre
"""
import queue
import socket
import logging
import argparse
import selectors
import threading
import multiprocessing
import multiprocessing.synchronize

from multiprocessing import connection
from multiprocessing.reduction import recv_handle

from typing import List, Optional, Tuple

from ...common.flag import flags
from ...common.utils import is_threadless
from ...common.logger import Logger
from ...common.constants import DEFAULT_LOCAL_EXECUTOR

from ..event import EventQueue

from .local import LocalExecutor
from .executors import ThreadlessPool

logger = logging.getLogger(__name__)


flags.add_argument(
    '--local-executor',
    action='store_true',
    default=DEFAULT_LOCAL_EXECUTOR,
    help='Default: ' + ('True' if DEFAULT_LOCAL_EXECUTOR else 'False') + '.  ' +
    'Disabled by default.  When enabled acceptors will make use of ' +
    'local (same process) executor instead of distributing load across ' +
    'remote (other process) executors.  Enable this option to achieve CPU affinity between ' +
    'acceptors and executors, instead of using underlying OS kernel scheduling algorithm.',
)


class Acceptor(multiprocessing.Process):
    """Work acceptor process.

    On start-up, `Acceptor` accepts a file descriptor which will be used to
    accept new work.  File descriptor is accepted over a `fd_queue` which is
    closed immediately after receiving the descriptor.

    `Acceptor` goes on to listen for new work over the received server socket.
    By default, `Acceptor` will spawn a new thread to handle each work.

    However, when `--threadless` option is enabled, `Acceptor` process
    will also pre-spawns a
    :class:`~proxy.core.acceptor.threadless.Threadless` process during
    start-up.  Accepted work is passed to these
    :class:`~proxy.core.acceptor.threadless.Threadless` processes.
    `Acceptor` process shares accepted work with a
    :class:`~proxy.core.acceptor.threadless.Threadless` process over
    it's dedicated pipe.

    TODO(abhinavsingh): Open questions::

       1. Instead of starting
          :class:`~proxy.core.acceptor.threadless.Threadless` process,
          can we work with a
          :class:`~proxy.core.acceptor.threadless.Threadless` thread?
       2. What are the performance implications of sharing fds between
          threads vs processes?
       3. How much performance degradation happens when acceptor and
          threadless processes are running on separate CPU cores?
       4. Can we ensure both acceptor and threadless process are pinned to
          the same CPU core?

    """

    def __init__(
            self,
            idd: int,
            fd_queue: connection.Connection,
            flags: argparse.Namespace,
            lock: multiprocessing.synchronize.Lock,
            executor_queues: List[connection.Connection],
            executor_pids: List[int],
            executor_locks: List[multiprocessing.synchronize.Lock],
            event_queue: Optional[EventQueue] = None,
    ) -> None:
        super().__init__()
        self.flags = flags
        # Eventing core queue
        self.event_queue = event_queue
        # Index assigned by `AcceptorPool`
        self.idd = idd
        # Mutex used for synchronization with acceptors
        self.lock = lock
        # Queue over which server socket fd is received on start-up
        self.fd_queue: connection.Connection = fd_queue
        # Available executors
        self.executor_queues = executor_queues
        self.executor_pids = executor_pids
        self.executor_locks = executor_locks
        # Selector
        self.running = multiprocessing.Event()
        self.selector: Optional[selectors.DefaultSelector] = None
        # File descriptor used to accept new work
        # Currently, a socket fd is assumed.
        self.sock: Optional[socket.socket] = None
        # Internals
        self._total: Optional[int] = None
        self._local: Optional[LocalExecutor] = None

    def run_once(self) -> None:
        if self.selector is not None:
            events = self.selector.select(timeout=1)
            if len(events) == 0:
                return
            locked = False
            try:
                if self.lock.acquire(block=False):
                    locked = True
                    for _, mask in events:
                        if mask & selectors.EVENT_READ:
                            if self.sock is not None:
                                conn, addr = self.sock.accept()
                                logging.debug(
                                    'Accepting new work#{0}'.format(conn.fileno()),
                                )
                                if self.flags.local_executor:
                                    assert self._local
                                    self._local.evq.put((conn, addr))
                                else:
                                    self._work(conn, addr or None)
            except BlockingIOError:
                pass
            finally:
                if locked:
                    self.lock.release()

    def run(self) -> None:
        Logger.setup(
            self.flags.log_file, self.flags.log_level,
            self.flags.log_format,
        )
        self.selector = selectors.DefaultSelector()
        # TODO: Use selector on fd_queue so that we can
        # dynamically accept from new fds.
        fileno = recv_handle(self.fd_queue)
        self.fd_queue.close()
        # TODO: Convert to socks i.e. list of fds
        self.sock = socket.fromfd(
            fileno,
            family=self.flags.family,
            type=socket.SOCK_STREAM,
        )
        try:
            if self.flags.local_executor:
                self._start_local()
            self.selector.register(self.sock, selectors.EVENT_READ)
            while not self.running.is_set():
                self.run_once()
        except KeyboardInterrupt:
            pass
        finally:
            self.selector.unregister(self.sock)
            if self.flags.local_executor:
                self._stop_local()
            self.sock.close()
            logger.debug('Acceptor#%d shutdown', self.idd)

    def _start_local(self) -> None:
        assert self.sock
        self._local = LocalExecutor(
            self.idd,
            self.flags,
            self.sock,
            queue.Queue(),
            self.executor_queues,
            self.executor_pids,
            self.executor_locks,
            self.event_queue,
        )
        self._local.daemon = True
        self._local.start()

    def _stop_local(self) -> None:
        if self._local is not None:
            self._local.evq.put(False)
            self._local.join()

    def _work(self, conn: socket.socket, addr: Optional[Tuple[str, int]]) -> None:
        self._total = self._total or 0
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
                'Dispatched work#{0}.{1}.{2} to worker#{3}'.format(
                    conn.fileno(), self.idd, self._total, index,
                ),
            )
        else:
            _, thread = ThreadlessPool.start_threaded_work(
                self.flags,
                conn,
                addr,
                event_queue=self.event_queue,
                publisher_id=self.__class__.__name__,
            )
            logger.debug(
                'Started work#{0}.{1}.{2} in thread#{3}'.format(
                    conn.fileno(), self.idd, self._total, thread.ident,
                ),
            )
        self._total += 1
