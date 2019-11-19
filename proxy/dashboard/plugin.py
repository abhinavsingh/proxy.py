# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any

from ..common.utils import bytes_
from ..common.flags import Flags
from ..http.websocket import WebsocketFrame
from ..core.connection import TcpClientConnection
from ..core.event import EventQueue


class ProxyDashboardWebsocketPlugin(ABC):
    """Abstract class for plugins extending dashboard websocket API."""

    def __init__(
            self,
            flags: Flags,
            client: TcpClientConnection,
            event_queue: EventQueue) -> None:
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    @abstractmethod
    def methods(self) -> List[str]:
        """Return list of methods that this plugin will handle."""
        pass

    @abstractmethod
    def handle_message(self, message: Dict[str, Any]) -> None:
        """Handle messages for registered methods."""
        pass

    def reply(self, data: Dict[str, Any]) -> None:
        self.client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps(data))))
