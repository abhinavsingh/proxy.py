# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       http
"""
import argparse
import socket
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from ...common.types import Readables, Writables
from ...core.connection import TcpClientConnection
from ...core.event import EventQueue
from ..parser import HttpParser
from ..websocket import WebsocketFrame


class HttpWebServerBasePlugin(ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            uid: UUID,
            flags: argparse.Namespace,
            client: TcpClientConnection,
            event_queue: EventQueue,
    ):
        self.uid = uid
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__      # pragma: no cover

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
            self,
    ) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []  # pragma: no cover

    # @abstractmethod
    def write_to_descriptors(self, w: Writables) -> bool:
        """Implementations must now write/flush data over the socket.

        Note that buffer management is in-build into the connection classes.
        Hence implementations MUST call
        :meth:`~proxy.core.connection.connection.TcpConnection.flush`
        here, to send any buffered data over the socket.
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

    def on_client_connection_close(self) -> None:
        """Client has closed the connection, do any clean up task now."""
        pass

    @abstractmethod
    def on_websocket_open(self) -> None:
        """Called when websocket handshake has finished."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Handle websocket frame."""
        raise NotImplementedError()     # pragma: no cover

    # Deprecated since v2.4.0
    #
    # Instead use on_client_connection_close.
    #
    # This callback is no longer invoked.  Kindly
    # update your plugin before upgrading to v2.4.0.
    #
    # @abstractmethod
    # def on_websocket_close(self) -> None:
    #     """Called when websocket connection has been closed."""
    #     raise NotImplementedError()     # pragma: no cover

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use this method to override default access log format (see
        DEFAULT_WEB_ACCESS_LOG_FORMAT) or to add/update/modify passed context
        for usage by default access logger.

        Return updated log context to use for default logging format, OR
        Return None if plugin has logged the request.
        """
        return context
