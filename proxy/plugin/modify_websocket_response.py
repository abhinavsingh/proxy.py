# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from ..http.proxy import HttpProxyBasePlugin
from ..http.websocket import WebsocketFrame


class ModifyWebsocketResponsePlugin(HttpProxyBasePlugin):
    """Inspect/Modify/Send custom websocket responses."""

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        # Parse the response.
        # Note that these chunks also include headers
        remaining = chunk.tobytes()
        while len(remaining) > 0:
            response = WebsocketFrame()
            remaining = response.parse(remaining)
            self.client.queue(
                memoryview(
                    WebsocketFrame.text(b'modified websocket response'),
                ),
            )
        return memoryview(b'')
