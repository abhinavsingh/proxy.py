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
       acceptors
       pre
"""
import logging
import argparse
import multiprocessing
from typing import TYPE_CHECKING, Any, List, Optional
from multiprocessing import connection
from multiprocessing.reduction import send_handle

from .acceptor import Acceptor
from ..listener import ListenerPool
from ...common.flag import flags
from ...common.constants import DEFAULT_NUM_ACCEPTORS


if TYPE_CHECKING:   # pragma: no cover
    from ..event import EventQueue

logger = logging.getLogger(__name__)


flags.add_argument(
    '--num-acceptors',
    type=int,
    default=DEFAULT_NUM_ACCEPTORS,
    help='Defaults to number of CPU cores.',
)


class AcceptorPool:
    """AcceptorPool is a helper class which pre-spawns
    :py:class:`~proxy.core.acceptor.acceptor.Acceptor` processes to
    utilize all available CPU cores for accepting new work.

    A file descriptor to consume work from is shared with
    :py:class:`~proxy.core.acceptor.acceptor.Acceptor` processes over a
    pipe.  Each :py:class:`~proxy.core.acceptor.acceptor.Acceptor`
    process then concurrently accepts new work over the shared file
    descriptor.

    Example usage:

        with AcceptorPool(flags=...) as pool:
            while True:
                time.sleep(1)

    `flags.work_klass` must implement :py:class:`~proxy.core.work.Work` class.
    """

    def __init__(
            self,
            flags: argparse.Namespace,
            listeners: ListenerPool,
            executor_queues: List[connection.Connection],
            executor_pids: List[int],
            executor_locks: List['multiprocessing.synchronize.Lock'],
            event_queue: Optional['EventQueue'] = None,
    ) -> None:
        self.flags = flags
        # File descriptor to use for accepting new work
        self.listeners: ListenerPool = listeners
        # Available executors
        self.executor_queues: List[connection.Connection] = executor_queues
        self.executor_pids: List[int] = executor_pids
        self.executor_locks: List['multiprocessing.synchronize.Lock'] = executor_locks
        # Eventing core queue
        self.event_queue: Optional['EventQueue'] = event_queue
        # Acceptor process instances
        self.acceptors: List[Acceptor] = []
        # Fd queues used to share file descriptor with acceptor processes
        self.fd_queues: List[connection.Connection] = []
        # Internals
        self.lock = multiprocessing.Lock()
        # self.semaphore = multiprocessing.Semaphore(0)

    def __enter__(self) -> 'AcceptorPool':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def setup(self) -> None:
        """Setup acceptors."""
        self._start()
        execution_mode = (
            'threadless (local)'
            if self.flags.local_executor
            else 'threadless (remote)'
        ) if self.flags.threadless else 'threaded'
        logger.info(
            'Started %d acceptors in %s mode' % (
                self.flags.num_acceptors,
                execution_mode,
            ),
        )
        # Send file descriptor to all acceptor processes.
        for index in range(self.flags.num_acceptors):
            self.fd_queues[index].send(len(self.listeners.pool))
            for listener in self.listeners.pool:
                fd = listener.fileno()
                assert fd is not None
                send_handle(
                    self.fd_queues[index],
                    fd,
                    self.acceptors[index].pid,
                )
            self.fd_queues[index].close()

    def shutdown(self) -> None:
        logger.info('Shutting down %d acceptors' % self.flags.num_acceptors)
        for acceptor in self.acceptors:
            acceptor.running.set()
        for acceptor in self.acceptors:
            acceptor.join(timeout=10)
        logger.debug('Acceptors shutdown')

    def _start(self) -> None:
        """Start acceptor processes."""
        for acceptor_id in range(self.flags.num_acceptors):
            work_queue = multiprocessing.Pipe()
            acceptor = Acceptor(
                idd=acceptor_id,
                fd_queue=work_queue[1],
                flags=self.flags,
                lock=self.lock,
                # semaphore=self.semaphore,
                event_queue=self.event_queue,
                executor_queues=self.executor_queues,
                executor_pids=self.executor_pids,
                executor_locks=self.executor_locks,
            )
            acceptor.start()
            logger.debug(
                'Started acceptor#%d process %d',
                acceptor_id,
                acceptor.pid,
            )
            self.acceptors.append(acceptor)
            self.fd_queues.append(work_queue[0])
