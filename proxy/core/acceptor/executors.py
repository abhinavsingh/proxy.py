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

from multiprocessing import connection

from typing import Optional, List, Type
from types import TracebackType

from .work import Work
from .threadless import Threadless

from ..event import EventQueue
from ..event import EventQueue

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
            logger.info('Started {0} threadless workers'.format(
                self.flags.num_workers))

    def shutdown(self) -> None:
        """Shutdown threadless processes."""
        if is_threadless(self.flags.threadless, self.flags.threaded):
            for _ in range(self.flags.num_workers):
                self._shutdown_worker()
            logger.info('Stopped {0} threadless workers'.format(
                self.flags.num_workers))

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
