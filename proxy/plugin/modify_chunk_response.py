# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser, httpParserTypes


class ModifyChunkResponsePlugin(HttpProxyBasePlugin):
    """Accumulate & modify chunk responses as received from upstream."""

    DEFAULT_CHUNKS = [
        b'modify',
        b'chunk',
        b'response',
        b'plugin',
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Create a new http protocol parser for response payloads
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)

    def handle_upstream_chunk(self, chunk: memoryview) -> Optional[memoryview]:
        # Parse the response.
        # Note that these chunks also include headers
        self.response.parse(chunk)
        # If response is complete, modify and dispatch to client
        if self.response.is_complete:
            # Queue our custom chunk if response is chunked encoded
            # otherwise queue the original response to client
            if self.response.is_chunked_encoded:
                self.response.body = b'\n'.join(self.DEFAULT_CHUNKS) + b'\n'
            self.client.queue(memoryview(self.response.build_response()))
        # Avoid returning chunk straight to client
        return None
