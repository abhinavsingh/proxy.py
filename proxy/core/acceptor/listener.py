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
import os
import socket
import logging
import argparse
from typing import Any, Optional

from ...common.flag import flags
from ...common.constants import (
    DEFAULT_PORT, DEFAULT_BACKLOG, DEFAULT_PORT_FILE, DEFAULT_IPV4_HOSTNAME,
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
    default=str(DEFAULT_IPV4_HOSTNAME),
    help='Default: 127.0.0.1. Server IP address.',
)

flags.add_argument(
    '--port',
    type=int,
    default=DEFAULT_PORT,
    help='Default: 8899. Server port.',
)

flags.add_argument(
    '--port-file',
    type=str,
    default=DEFAULT_PORT_FILE,
    help='Default: None. Save server port numbers. Useful when using --port=0 ephemeral mode.',
)

flags.add_argument(
    '--unix-socket-path',
    type=str,
    default=None,
    help='Default: None. Unix socket path to use.  ' +
    'When provided --host and --port flags are ignored',
)

logger = logging.getLogger(__name__)


class Listener:

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags
        # Set after binding to a port.
        # Stored here separately because ephemeral ports can be used.
        self._port: Optional[int] = None
        self._socket: Optional[socket.socket] = None

    def __enter__(self) -> 'Listener':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def fileno(self) -> Optional[int]:
        if not self._socket:
            return None
        return self._socket.fileno()

    def setup(self) -> None:
        if self.flags.unix_socket_path:
            self._listen_unix_socket()
        else:
            self._listen_server_port()
        if self.flags.unix_socket_path:
            logger.info(
                'Listening on %s' %
                self.flags.unix_socket_path,
            )
        else:
            logger.info(
                'Listening on %s:%s' %
                (self.flags.hostname, self._port),
            )

    def shutdown(self) -> None:
        assert self._socket
        self._socket.close()
        if self.flags.unix_socket_path:
            os.remove(self.flags.unix_socket_path)

    def _listen_unix_socket(self) -> None:
        self._socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._socket.bind(self.flags.unix_socket_path)
        self._socket.listen(self.flags.backlog)
        self._socket.setblocking(False)

    def _listen_server_port(self) -> None:
        self._socket = socket.socket(self.flags.family, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # self._socket.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)
        self._socket.bind((str(self.flags.hostname), self.flags.port))
        self._socket.listen(self.flags.backlog)
        self._socket.setblocking(False)
        self._port = self._socket.getsockname()[1]
