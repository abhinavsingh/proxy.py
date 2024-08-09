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
from abc import abstractmethod
from typing import TYPE_CHECKING, Any


try:
    if TYPE_CHECKING:  # pragma: no cover
        from paramiko.channel import Channel

        from ...common.types import HostPort
except ImportError:  # pragma: no cover
    pass

logger = logging.getLogger(__name__)


class BaseSshTunnelHandler:

    def __init__(self, flags: argparse.Namespace) -> None:
        self.flags = flags

    @abstractmethod
    def on_connection(
        self,
        chan: 'Channel',
        origin: 'HostPort',
        server: 'HostPort',
    ) -> None:
        raise NotImplementedError()

    @abstractmethod
    def shutdown(self) -> None:
        raise NotImplementedError()


class BaseSshTunnelListener:

    def __init__(
        self,
        flags: argparse.Namespace,
        handler: BaseSshTunnelHandler,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.flags = flags
        self.handler = handler

    def __enter__(self) -> 'BaseSshTunnelListener':
        self.setup()
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()

    @abstractmethod
    def is_alive(self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def is_active(self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def setup(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    def shutdown(self) -> None:
        raise NotImplementedError()
