# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import ABC, abstractmethod
from typing import List, Tuple

from ..websocket import WebsocketFrame
from ..parser import HttpParser

from ...common.flags import Flags
from ...core.connection import TcpClientConnection
from ...core.event import EventQueue


class HttpWebServerBasePlugin(ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            uid: str,
            flags: Flags,
            client: TcpClientConnection,
            event_queue: EventQueue):
        self.uid = uid
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    @abstractmethod
    def routes(self) -> List[Tuple[int, str]]:
        """Return List(protocol, path) that this plugin handles."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def handle_request(self, request: HttpParser) -> None:
        """Handle the request and serve response."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_open(self) -> None:
        """Called when websocket handshake has finished."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Handle websocket frame."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_close(self) -> None:
        """Called when websocket connection has been closed."""
        raise NotImplementedError()     # pragma: no cover
