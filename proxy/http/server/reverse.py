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

from . import HttpWebServerBasePlugin, httpProtocolTypes
from .. import Url
from ..parser import HttpParser
from ..exception import HttpProtocolException
from ...core.base import TcpUpstreamConnectionHandler
from ...common.utils import text_
from ...common.constants import (
    DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT,
    DEFAULT_REVERSE_PROXY_ACCESS_LOG_FORMAT,
)


if TYPE_CHECKING:
    from .plugin import ReverseProxyBasePlugin


logger = logging.getLogger(__name__)


class ReverseProxy(TcpUpstreamConnectionHandler, HttpWebServerBasePlugin):
    """Extend in-built Web Server to add Reverse Proxy capabilities."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.choice: Optional[Url] = None
        self.reverse: Dict[str, List[bytes]] = {}

    def handle_upstream_data(self, raw: memoryview) -> None:
        self.client.queue(raw)

    def routes(self) -> List[Tuple[int, str]]:
        reverse: List[Tuple[str, List[bytes]]] = []
        for klass in self.flags.plugins[b'ReverseProxyBasePlugin']:
            instance: 'ReverseProxyBasePlugin' = klass()
            reverse.extend(instance.routes())
        r = []
        for (route, upstreams) in reverse:
            r.append((httpProtocolTypes.HTTP, route))
            r.append((httpProtocolTypes.HTTPS, route))
            self.reverse[route] = upstreams
        return r

    def handle_request(self, request: HttpParser) -> None:
        # TODO: Core must be capable of dispatching a context
        # with each invocation of handle request callback.
        #
        # Example, here we don't know which of our registered
        # route actually matched.
        #
        for route in self.reverse.keys():
            pattern = re.compile(route)
            if pattern.match(text_(request.path)):
                self.choice = Url.from_bytes(
                    random.choice(self.reverse[route]),
                )
                break
        assert self.choice and self.choice.hostname
        port = self.choice.port or \
            DEFAULT_HTTP_PORT \
            if self.choice.scheme == b'http' \
            else DEFAULT_HTTPS_PORT
        self.initialize_upstream(text_(self.choice.hostname), port)
        assert self.upstream
        try:
            self.upstream.connect()
            if self.choice.scheme == b'https':
                self.upstream.wrap(
                    text_(
                        self.choice.hostname,
                    ), ca_file=str(self.flags.ca_file),
                )
            self.upstream.queue(memoryview(request.build()))
        except ConnectionRefusedError:
            raise HttpProtocolException(
                'Connection refused by upstream server {0}:{1}'.format(
                    text_(self.choice.hostname), port,
                ),
            )

    def on_client_connection_close(self) -> None:
        if self.upstream and not self.upstream.closed:
            logger.debug('Closing upstream server connection')
            self.upstream.close()
            self.upstream = None

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        context.update({
            'upstream_proxy_pass': str(self.choice) if self.choice else None,
        })
        logger.info(DEFAULT_REVERSE_PROXY_ACCESS_LOG_FORMAT.format_map(context))
        return None
