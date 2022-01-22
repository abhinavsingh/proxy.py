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
import argparse
from abc import ABC, abstractmethod
from typing import Any, Optional

from ...common.flag import flags
from ...common.constants import DEFAULT_BACKLOG


flags.add_argument(
    '--backlog',
    type=int,
    default=DEFAULT_BACKLOG,
    help='Default: 100. Maximum number of pending connections to proxy server.',
)

logger = logging.getLogger(__name__)


class BaseListener(ABC):
    """Base listener class.

    For usage provide a listen method implementation."""

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags
        self._socket: Optional[socket.socket] = None

    @abstractmethod
    def listen(self) -> socket.socket:
        raise NotImplementedError()

    def __enter__(self) -> 'BaseListener':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def fileno(self) -> Optional[int]:
        if not self._socket:
            return None
        return self._socket.fileno()

    def setup(self) -> None:
        self._socket = self.listen()

    def shutdown(self) -> None:
        assert self._socket
        self._socket.close()
        if self.flags.unix_socket_path:
            os.remove(self.flags.unix_socket_path)
