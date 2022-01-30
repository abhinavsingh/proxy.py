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
import socket
import logging

from .base import BaseListener
from ...common.flag import flags


flags.add_argument(
    '--unix-socket-path',
    type=str,
    default=None,
    help='Default: None. Unix socket path to use.  ' +
    'When provided --host and --port flags are ignored',
)

logger = logging.getLogger(__name__)


class UnixSocketListener(BaseListener):
    """Unix socket domain listener."""

    def listen(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(self.flags.unix_socket_path)
        sock.listen(self.flags.backlog)
        sock.setblocking(False)
        logger.info(
            'Listening on %s' %
            self.flags.unix_socket_path,
        )
        return sock

    def shutdown(self) -> None:
        super().shutdown()
        if self.flags.unix_socket_path:
            os.remove(self.flags.unix_socket_path)
