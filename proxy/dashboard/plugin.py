# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import argparse
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..core.event import EventQueue
from ..common.utils import bytes_
from ..http.websocket import WebsocketFrame
from ..core.connection import TcpClientConnection


class ProxyDashboardWebsocketPlugin(ABC):
    """Abstract class for plugins extending dashboard websocket API."""

    def __init__(
            self,
            flags: argparse.Namespace,
            client: TcpClientConnection,
            event_queue: EventQueue,
    ) -> None:
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    @abstractmethod
    def methods(self) -> List[str]:
        """Return list of methods that this plugin will handle."""
        pass    # pragma: no cover

    def connected(self) -> None:
        """Invoked when client websocket handshake finishes."""
        pass    # pragma: no cover

    @abstractmethod
    def handle_message(self, message: Dict[str, Any]) -> None:
        """Handle messages for registered methods."""
        pass    # pragma: no cover

    def disconnected(self) -> None:
        """Invoked when client websocket connection gets closed."""
        pass    # pragma: no cover

    def reply(self, data: Dict[str, Any]) -> None:
        self.client.queue(
            memoryview(
                WebsocketFrame.text(
                    bytes_(
                        json.dumps(data),
                    ),
                ),
            ),
        )
