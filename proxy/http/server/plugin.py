# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket
import argparse

from abc import ABC, abstractmethod
from typing import List, Tuple
from uuid import UUID

from ..websocket import WebsocketFrame
from ..parser import HttpParser

from ...common.types import Readables, Writables
from ...core.connection import TcpClientConnection
from ...core.event import EventQueue


class HttpWebServerBasePlugin(ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            uid: UUID,
            flags: argparse.Namespace,
            client: TcpClientConnection,
            event_queue: EventQueue):
        self.uid = uid
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    # TODO(abhinavsingh): get_descriptors, write_to_descriptors, read_from_descriptors
    # can be placed into their own abstract class which can then be shared by
    # HttpProxyBasePlugin, HttpWebServerBasePlugin and HttpProtocolHandlerPlugin class.
    #
    # Currently code has been shamelessly copied.  Also these methods are not
    # marked as abstract to avoid breaking custom plugins written by users for
    # previous versions of proxy.py
    #
    # Since 3.4.0
    #
    # @abstractmethod
    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []  # pragma: no cover

    # @abstractmethod
    def write_to_descriptors(self, w: Writables) -> bool:
        """Implementations must now write/flush data over the socket.

        Note that buffer management is in-build into the connection classes.
        Hence implementations MUST call `flush` here, to send any buffered data
        over the socket.
        """
        return False  # pragma: no cover

    # @abstractmethod
    def read_from_descriptors(self, r: Readables) -> bool:
        """Implementations must now read data over the socket."""
        return False  # pragma: no cover

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
