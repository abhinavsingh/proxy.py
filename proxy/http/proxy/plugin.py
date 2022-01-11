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

from abc import ABC
from typing import Any, Dict, Optional, Tuple, TYPE_CHECKING

from ..mixins import TlsInterceptionPropertyMixin

from ..parser import HttpParser
from ..descriptors import DescriptorsHandlerMixin

from ...core.event import EventQueue
from ...core.connection import TcpClientConnection

if TYPE_CHECKING:
    from ...core.connection import UpstreamConnectionPool


class HttpProxyBasePlugin(
        DescriptorsHandlerMixin,
        TlsInterceptionPropertyMixin,
        ABC
):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            uid: str,
            flags: argparse.Namespace,
            client: TcpClientConnection,
            event_queue: EventQueue,
            upstream_conn_pool: Optional['UpstreamConnectionPool'] = None,
    ) -> None:
        self.uid = uid                  # pragma: no cover
        self.flags = flags              # pragma: no cover
        self.client = client            # pragma: no cover
        self.event_queue = event_queue  # pragma: no cover
        self.upstream_conn_pool = upstream_conn_pool

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__      # pragma: no cover

    def resolve_dns(self, host: str, port: int) -> Tuple[Optional[str], Optional[Tuple[str, int]]]:
        """Resolve upstream server host to an IP address.

        Optionally also override the source address to use for
        connection with upstream server.

        For upstream IP:
        Return None to use default resolver available to the system.
        Return IP address as string to use your custom resolver.

        For source address:
        Return None to use default source address
        Return 2-tuple representing (host, port) to use as source address
        """
        return None, None

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Handler called just before Proxy upstream connection is established.

        Return optionally modified request object.
        If None is returned, upstream connection won't be established.

        Raise HttpRequestRejected or HttpProtocolException directly to drop the connection."""
        return request  # pragma: no cover

    # Since 3.4.0
    #
    # @abstractmethod
    def handle_client_data(
            self, raw: memoryview,
    ) -> Optional[memoryview]:
        """Handler called in special scenarios when an upstream server connection
        is never established.

        Essentially, if you return None from within before_upstream_connection,
        be prepared to handle_client_data and not handle_client_request.

        Only called after initial request from client has been received.

        Raise HttpRequestRejected to tear down the connection
        Return None to drop the connection
        """
        return raw  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Handler called before dispatching client request to upstream.

        Note: For pipelined (keep-alive) connections, this handler can be
        called multiple times, for each request sent to upstream.

        Note: If TLS interception is enabled, this handler can
        be called multiple times if client exchanges multiple
        requests over same SSL session.

        Return optionally modified request object to dispatch to upstream.
        Return None to drop the request data, e.g. in case a response has already been queued.
        Raise HttpRequestRejected or HttpProtocolException directly to
        tear down the connection with client.

        """
        return request  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        """Handler called right after receiving raw response from upstream server.

        For HTTPS connections, chunk will be encrypted unless
        TLS interception is also enabled."""
        return chunk  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def on_upstream_connection_close(self) -> None:
        """Handler called right after upstream connection has been closed."""
        pass  # pragma: no cover

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use this method to override default access log format (see
        DEFAULT_HTTP_ACCESS_LOG_FORMAT and DEFAULT_HTTPS_ACCESS_LOG_FORMAT) and to
        add/update/modify/delete context for next plugin.on_access_log invocation.

        This is specially useful if a plugins want to provide extra context
        in the access log which may not available within other plugins' context or even
        in proxy.py core.

        Returns Log context or None.  If plugin chooses to access log, they ideally
        must return None to prevent other plugin.on_access_log invocation.
        """
        return context

    def do_intercept(self) -> bool:
        return self.tls_interception_enabled
