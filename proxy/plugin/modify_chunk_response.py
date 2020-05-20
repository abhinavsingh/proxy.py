# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional, Any, List

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin


class ModifyChunkResponsePlugin(HttpProxyBasePlugin):
    """Accumulate & modify chunk responses as received from upstream."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.chunks: List[bytes] = []

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        # Accumulate all chunks and return empty string as callback response,
        # effectively delaying dispatching response to the client.
        self.chunks.append(chunk.tobytes())
        return memoryview(b'')

    def on_upstream_connection_close(self) -> None:
        # Modify chunks here before dispatching to client
        self.client.queue(memoryview(b''.join(self.chunks)))
        # Upstream connection is closed hence explicitly
        # invoke client.flush to ensure client receives
        # response before connection is dropped
        self.client.flush()
