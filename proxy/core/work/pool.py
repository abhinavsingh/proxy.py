# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
import argparse
import multiprocessing
from typing import TYPE_CHECKING, Any, List, Type, TypeVar, Optional
from multiprocessing import connection

from ...common.flag import flags
from ...common.constants import (
    DEFAULT_THREADLESS, DEFAULT_NUM_WORKERS, DEFAULT_THREADLESS_POOL_KLASS,
)


if TYPE_CHECKING:   # pragma: no cover
    from ..event import EventQueue
    from .threadless import Threadless

T = TypeVar('T', bound='Threadless[Any]')

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

flags.add_argument(
    '--threadless-pool-klass',
    type=str,
    default=DEFAULT_THREADLESS_POOL_KLASS,
    help='Default: ' + DEFAULT_THREADLESS_POOL_KLASS +
    '.  Threadless pool klass.',
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
    """

    def __init__(
        self,
        flags: argparse.Namespace,
        executor_klass: Type['T'],
        event_queue: Optional['EventQueue'] = None,
    ) -> None:
        self.flags = flags
        self.event_queue = event_queue
        # Threadless worker communication states
        self.work_queues: List[connection.Connection] = []
        self.work_pids: List[int] = []
        self.work_locks: List['multiprocessing.synchronize.Lock'] = []
        # List of threadless workers
        self._executor_klass = executor_klass
        # FIXME: Instead of Any type must be the executor klass
        self._workers: List[Any] = []
        self._processes: List[multiprocessing.Process] = []

    def __enter__(self) -> 'ThreadlessPool':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def setup(self) -> None:
        """Setup threadless processes."""
        if self.flags.threadless:
            for index in range(self.flags.num_workers):
                self._start_worker(index)
            logger.info(
                'Started {0} threadless workers'.format(
                    self.flags.num_workers,
                ),
            )

    def shutdown(self) -> None:
        """Shutdown threadless processes."""
        if self.flags.threadless:
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
        w = self._executor_klass(
            iid=str(index),
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
        for _ in range(self.flags.num_workers):
            pid = self.work_pids[-1]
            self._processes.pop().join()
            self._workers.pop()
            self.work_pids.pop()
            self.work_queues.pop().close()
            logger.debug('Stopped threadless process#%d', pid)
        self.work_locks = []
