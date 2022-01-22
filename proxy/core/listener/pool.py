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
from typing import TYPE_CHECKING, Any, List, Type

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
            self.add(UnixSocketListener)
        else:
            self.add(TcpSocketListener)
        for port in self.flags.ports:
            self.add(TcpSocketListener, port=port)

    def shutdown(self) -> None:
        for listener in self.pool:
            listener.shutdown()
        self.pool.clear()

    def add(self, klass: Type['BaseListener'], **kwargs: Any) -> None:
        listener = klass(flags=self.flags, **kwargs)
        listener.setup()
        self.pool.append(listener)
