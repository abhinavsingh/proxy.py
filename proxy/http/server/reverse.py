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
import random
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Tuple, Optional

from proxy.http import Url
from proxy.core.base import TcpUpstreamConnectionHandler
from proxy.http.parser import HttpParser
from proxy.http.server import HttpWebServerBasePlugin
from proxy.common.utils import text_
from proxy.http.exception import HttpProtocolException
from proxy.common.constants import (
    HTTPS_PROTO, DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT,
    DEFAULT_REVERSE_PROXY_ACCESS_LOG_FORMAT,
)
from ...common.types import Readables, Writables, Descriptors


if TYPE_CHECKING:   # pragma: no cover
    from .plugin import ReverseProxyBasePlugin


logger = logging.getLogger(__name__)


class ReverseProxy(TcpUpstreamConnectionHandler, HttpWebServerBasePlugin):
    """Extend in-built Web Server to add Reverse Proxy capabilities."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.choice: Optional[Url] = None
        self.plugins: List['ReverseProxyBasePlugin'] = []
        for klass in self.flags.plugins[b'ReverseProxyBasePlugin']:
            plugin: 'ReverseProxyBasePlugin' = klass(
                self.uid, self.flags, self.client, self.event_queue, self.upstream_conn_pool,
            )
            self.plugins.append(plugin)
        self._upstream_proxy_pass: Optional[str] = None

    def do_upgrade(self, request: HttpParser) -> bool:
        """Signal web protocol handler to not upgrade websocket requests by default."""
        return False

    def handle_upstream_data(self, raw: memoryview) -> None:
        # TODO: Parse response and implement plugin hook per parsed response object
        # This will give plugins a chance to modify the responses before dispatching to client
        self.client.queue(raw)

    def routes(self) -> List[Tuple[int, str]]:
        r = []
        for plugin in self.plugins:
            for route in plugin.regexes():
                for proto in plugin.protocols():
                    r.append((proto, route))
        return r

    def handle_request(self, request: HttpParser) -> None:
        # before_routing
        for plugin in self.plugins:
            r = plugin.before_routing(request)
            if r is None:
                raise HttpProtocolException('before_routing closed connection')
            request = r

        needs_upstream = False

        # routes
        for plugin in self.plugins:
            for route in plugin.routes():
                # Static routes
                if isinstance(route, tuple):
                    pattern = re.compile(route[0])
                    if pattern.match(text_(request.path)):
                        self.choice = Url.from_bytes(
                            random.choice(route[1]),
                        )
                        break
                # Dynamic routes
                elif isinstance(route, str):
                    pattern = re.compile(route)
                    if pattern.match(text_(request.path)):
                        choice = plugin.handle_route(request, pattern)
                        if isinstance(choice, Url):
                            self.choice = choice
                            needs_upstream = True
                            self._upstream_proxy_pass = str(self.choice)
                        elif isinstance(choice, memoryview):
                            self.client.queue(choice)
                            self._upstream_proxy_pass = '{0} bytes'.format(len(choice))
                        else:
                            self.upstream = choice
                            self._upstream_proxy_pass = '{0}:{1}'.format(
                                *self.upstream.addr,
                            )
                        break
                else:
                    raise ValueError('Invalid route')

        if needs_upstream:
            assert self.choice and self.choice.hostname
            port = (
                self.choice.port or DEFAULT_HTTP_PORT
                if self.choice.scheme == b'http'
                else DEFAULT_HTTPS_PORT
            )
            self.initialize_upstream(text_(self.choice.hostname), port)
            assert self.upstream
            try:
                self.upstream.connect()
                if self.choice.scheme == HTTPS_PROTO:
                    self.upstream.wrap(
                        text_(
                            self.choice.hostname,
                        ),
                        as_non_blocking=True,
                        ca_file=self.flags.ca_file,
                    )
                request.path = self.choice.remainder
                self.upstream.queue(memoryview(request.build()))
            except ConnectionRefusedError:
                raise HttpProtocolException(  # pragma: no cover
                    'Connection refused by upstream server {0}:{1}'.format(
                        text_(self.choice.hostname),
                        port,
                    ),
                )

    def on_client_connection_close(self) -> None:
        if self.upstream and not self.upstream.closed:
            logger.debug('Closing upstream server connection')
            self.upstream.close()
            self.upstream = None

    def on_client_data(
        self,
        request: HttpParser,
        raw: memoryview,
    ) -> Optional[memoryview]:
        if request.is_websocket_upgrade:
            assert self.upstream
            self.upstream.queue(raw)
        return raw

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        context.update(
            {
                'upstream_proxy_pass': self._upstream_proxy_pass,
            },
        )
        log_handled = False
        for plugin in self.plugins:
            ctx = plugin.on_access_log(context)
            if ctx is None:
                log_handled = True
                break
            context = ctx
        if not log_handled:
            logger.info(DEFAULT_REVERSE_PROXY_ACCESS_LOG_FORMAT.format_map(context))
        return None

    async def get_descriptors(self) -> Descriptors:
        r, w = await super().get_descriptors()
        # TODO(abhinavsingh): We need to keep a mapping of plugin and
        # descriptors registered by them, so that within write/read blocks
        # we can invoke the right plugin callbacks.
        for plugin in self.plugins:
            plugin_read_desc, plugin_write_desc = await plugin.get_descriptors()
            r.extend(plugin_read_desc)
            w.extend(plugin_write_desc)
        return r, w

    async def read_from_descriptors(self, r: Readables) -> bool:
        for plugin in self.plugins:
            teardown = await plugin.read_from_descriptors(r)
            if teardown:
                return True
        return await super().read_from_descriptors(r)

    async def write_to_descriptors(self, w: Writables) -> bool:
        for plugin in self.plugins:
            teardown = await plugin.write_to_descriptors(w)
            if teardown:
                return True
        return await super().write_to_descriptors(w)
