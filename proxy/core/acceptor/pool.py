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
import argparse
import logging
import multiprocessing
import socket

from multiprocessing import connection
from multiprocessing.reduction import send_handle

from typing import List, Optional, Type
from types import TracebackType

from .acceptor import Acceptor
from .work import Work

from ..event import EventQueue

from ...common.utils import bytes_
from ...common.flag import flags
from ...common.constants import DEFAULT_BACKLOG, DEFAULT_IPV6_HOSTNAME
from ...common.constants import DEFAULT_NUM_ACCEPTORS, DEFAULT_PORT
from ...common.constants import DEFAULT_PID_FILE

logger = logging.getLogger(__name__)

# Lock shared by acceptors for
# sequential acceptance of work.
LOCK = multiprocessing.Lock()


flags.add_argument(
    '--pid-file',
    type=str,
    default=DEFAULT_PID_FILE,
    help='Default: None. Save parent process ID to a file.',
)

flags.add_argument(
    '--backlog',
    type=int,
    default=DEFAULT_BACKLOG,
    help='Default: 100. Maximum number of pending connections to proxy server',
)

flags.add_argument(
    '--hostname',
    type=str,
    default=str(DEFAULT_IPV6_HOSTNAME),
    help='Default: ::1. Server IP address.',
)

flags.add_argument(
    '--port', type=int, default=DEFAULT_PORT,
    help='Default: 8899. Server port.',
)

flags.add_argument(
    '--num-acceptors',
    type=int,
    default=DEFAULT_NUM_ACCEPTORS,
    help='Defaults to number of CPU cores.',
)

flags.add_argument(
    '--unix-socket-path',
    type=str,
    default=None,
    help='Default: None. Unix socket path to use.  ' +
    'When provided --host and --port flags are ignored',
)


class AcceptorPool:
    """AcceptorPool is a helper class which pre-spawns `Acceptor` processes
    to utilize all available CPU cores for accepting new work.

    A file descriptor to consume work from is shared with `Acceptor` processes
    over a pipe.  Each `Acceptor` process then concurrently accepts new work over
    the shared file descriptor.

    Example usage:

        with AcceptorPool(flags=..., work_klass=...) as pool:
            while True:
                time.sleep(1)

    `work_klass` must implement `work.Work` class.
    """

    def __init__(
        self, flags: argparse.Namespace,
        work_klass: Type[Work],
        executor_queues: List[connection.Connection] = [],
        executor_pids: List[int] = [],
        event_queue: Optional[EventQueue] = None,
    ) -> None:
        self.flags = flags
        # Eventing core queue
        self.event_queue: Optional[EventQueue] = event_queue
        # File descriptor to use for accepting new work
        self.socket: Optional[socket.socket] = None
        # Acceptor process instances
        self.acceptors: List[Acceptor] = []
        # Work queue used to share file descriptor with acceptor processes
        self.work_queues: List[connection.Connection] = []
        # Work class implementation
        self.work_klass: Type[Work] = work_klass
        self.executor_queues: List[connection.Connection] = executor_queues
        self.executor_pids: List[int] = executor_pids

    def __enter__(self) -> 'AcceptorPool':
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
        """Setup socket and acceptors."""
        self._write_pid_file()
        if self.flags.unix_socket_path:
            self._listen_unix_socket()
        else:
            self._listen_server_port()
        # Override flags.port to match the actual port
        # we are listening upon.  This is necessary to preserve
        # the server port when `--port=0` is used.
        assert self.socket
        self.flags.port = self.socket.getsockname()[1]
        self._start()
        # Send file descriptor to all acceptor processes.
        assert self.socket is not None
        for index in range(self.flags.num_acceptors):
            send_handle(
                self.work_queues[index],
                self.socket.fileno(),
                self.acceptors[index].pid,
            )
            self.work_queues[index].close()
        self.socket.close()

    def shutdown(self) -> None:
        logger.info('Shutting down %d acceptors' % self.flags.num_acceptors)
        for acceptor in self.acceptors:
            acceptor.running.set()
        for acceptor in self.acceptors:
            acceptor.join()
        if self.flags.unix_socket_path:
            os.remove(self.flags.unix_socket_path)
        self._delete_pid_file()
        logger.debug('Acceptors shutdown')

    def _listen_unix_socket(self) -> None:
        self.socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.flags.unix_socket_path)
        self.socket.listen(self.flags.backlog)
        self.socket.setblocking(False)

    def _listen_server_port(self) -> None:
        self.socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((str(self.flags.hostname), self.flags.port))
        self.socket.listen(self.flags.backlog)
        self.socket.setblocking(False)

    def _start(self) -> None:
        """Start acceptor processes."""
        for acceptor_id in range(self.flags.num_acceptors):
            work_queue = multiprocessing.Pipe()
            acceptor = Acceptor(
                idd=acceptor_id,
                work_queue=work_queue[1],
                flags=self.flags,
                work_klass=self.work_klass,
                lock=LOCK,
                event_queue=self.event_queue,
                executor_queues=self.executor_queues,
                executor_pids=self.executor_pids,
            )
            acceptor.start()
            logger.debug(
                'Started acceptor#%d process %d',
                acceptor_id,
                acceptor.pid,
            )
            self.acceptors.append(acceptor)
            self.work_queues.append(work_queue[0])
        logger.info('Started %d acceptors' % self.flags.num_acceptors)

    def _write_pid_file(self) -> None:
        if self.flags.pid_file is not None:
            # NOTE: Multiple instances of proxy.py running on
            # same host machine will currently result in overwriting the PID file
            with open(self.flags.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))

    def _delete_pid_file(self) -> None:
        if self.flags.pid_file and os.path.exists(self.flags.pid_file):
            os.remove(self.flags.pid_file)
