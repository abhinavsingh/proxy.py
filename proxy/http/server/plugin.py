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
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple, Optional

from ..parser import HttpParser
from ..websocket import WebsocketFrame
from ...core.event import EventQueue
from ..descriptors import DescriptorsHandlerMixin
from ...core.connection import TcpClientConnection


class HttpWebServerBasePlugin(DescriptorsHandlerMixin, ABC):
    """Web Server Plugin base.

    Can be used for registering URL route handlers and
    for managing custom middleware lifecycles.

    Route handler are invoked for matching / registered routes.
    While, middlewares are always invoked.  Notice that, middlewares
    are invoked twice for each request.  Once for incoming
    request and once for outgoing response.

    A plugin without any registered route is considered
    as a middleware.  Specify route to turn your plugin
    into a web server route handler."""

    def __init__(
            self,
            uid: str,
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

    # No longer abstract since v2.4.0
    #
    # @abstractmethod
    def on_websocket_open(self) -> None:
        """Called when websocket handshake has finished."""
        pass        # pragma: no cover

    # No longer abstract since v2.4.0
    #
    # @abstractmethod
    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Handle websocket frame."""
        return None     # pragma: no cover

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
