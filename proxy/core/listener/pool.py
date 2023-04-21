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
import itertools
from typing import TYPE_CHECKING, Any, List, Type

from .tcp import TcpSocketListener
from .unix import UnixSocketListener
from ...common.flag import flags
from ...common.constants import DEFAULT_LISTENER_POOL_KLASS


if TYPE_CHECKING:   # pragma: no cover
    from .base import BaseListener


flags.add_argument(
    '--listener-pool-klass',
    type=str,
    default=DEFAULT_LISTENER_POOL_KLASS,
    help='Default: ' + DEFAULT_LISTENER_POOL_KLASS +
    '.  Listener pool klass.',
)


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
        hostnames = {self.flags.hostname, *self.flags.hostnames}
        ports = set(self.flags.ports)
        if not self.flags.unix_socket_path:
            ports.add(self.flags.port)
        for hostname, port in itertools.product(hostnames, ports):
            self.add(TcpSocketListener, hostname=hostname, port=port)

    def shutdown(self) -> None:
        for listener in self.pool:
            listener.shutdown()
        self.pool.clear()

    def add(self, klass: Type['BaseListener'], **kwargs: Any) -> None:
        listener = klass(flags=self.flags, **kwargs)
        listener.setup()
        self.pool.append(listener)
