# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import re
import argparse
import mimetypes
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Union, Optional

from proxy.http.url import Url
from ..parser import HttpParser
from ..responses import NOT_FOUND_RESPONSE_PKT, okResponse
from ..websocket import WebsocketFrame
from ..connection import HttpClientConnection
from ...core.event import EventQueue
from ..descriptors import DescriptorsHandlerMixin
from ...common.utils import bytes_


if TYPE_CHECKING:   # pragma: no cover
    from ...core.connection import UpstreamConnectionPool


class HttpWebServerBasePlugin(DescriptorsHandlerMixin, ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            uid: str,
            flags: argparse.Namespace,
            client: HttpClientConnection,
            event_queue: EventQueue,
            upstream_conn_pool: Optional['UpstreamConnectionPool'] = None,
    ):
        self.uid = uid
        self.flags = flags
        self.client = client
        self.event_queue = event_queue
        self.upstream_conn_pool = upstream_conn_pool

    @staticmethod
    def serve_static_file(path: str, min_compression_length: int) -> memoryview:
        try:
            with open(path, 'rb') as f:
                content = f.read()
            content_type = mimetypes.guess_type(path)[0]
            if content_type is None:
                content_type = 'text/plain'
            headers = {
                b'Content-Type': bytes_(content_type),
                b'Cache-Control': b'max-age=86400',
            }
            return okResponse(
                content=content,
                headers=headers,
                min_compression_length=min_compression_length,
                # TODO: Should we really close or take advantage of keep-alive?
                conn_close=True,
            )
        except FileNotFoundError:
            return NOT_FOUND_RESPONSE_PKT

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


class ReverseProxyBasePlugin(ABC):
    """ReverseProxy base plugin class."""

    @abstractmethod
    def routes(self) -> List[Union[str, Tuple[str, List[bytes]]]]:
        """List of routes registered by plugin.

        There are 2 types of routes:

        1) Dynamic routes (str): Should be a regular expression
        2) Static routes (tuple): Contain 2 elements, a route regular expression
           and list of upstream urls to serve when the route matches.

        Static routes doesn't require you to implement the `handle_route` method.
        Reverse proxy core will automatically pick one of the configured upstream URL
        and serve it out-of-box.

        Dynamic routes are helpful when you want to dynamically match and serve upstream urls.
        To handle dynamic routes, you must implement the `handle_route` method, which
        must return the url to serve."""
        raise NotImplementedError()     # pragma: no cover

    def handle_route(self, request: HttpParser, pattern: re.Pattern) -> Url:
        """Implement this method if you have configured dynamic routes."""
        pass

    def regexes(self) -> List[str]:
        """Helper method to return list of route regular expressions."""
        routes = []
        for route in self.routes():
            if isinstance(route, str):
                routes.append(route)
            elif isinstance(route, tuple):
                routes.append(route[0])
            else:
                raise ValueError("Invalid route type")
        return routes
