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
from typing import TYPE_CHECKING, Any, List

from .tcp import TcpSocketListener
from .unix import UnixSocketListener

if TYPE_CHECKING:
    from .base import BaseListener


class ListenerPool:
    """Provides abstraction around starting multiple listeners
    based upon flags."""

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags
        self.pool: List['BaseListener'] = []

    def __enter__(self) -> 'ListenerPool':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    def setup(self) -> None:
        if self.flags.unix_socket_path:
            ulistener = UnixSocketListener(self.flags)
            ulistener.setup()
            self.pool.append(ulistener)
        else:
            listener = TcpSocketListener(self.flags)
            listener.setup()
            self.pool.append(listener)

    def shutdown(self) -> None:
        for listener in self.pool:
            listener.shutdown()
        self.pool.clear()
