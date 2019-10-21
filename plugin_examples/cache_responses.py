# -*- coding: utf-8 -*-
"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import tempfile
import time
import logging
from typing import Optional, BinaryIO

from core.flags import Flags
from core.connection import TcpClientConnection
from core.http_parser import HttpParser
from core.http_proxy import HttpProxyBasePlugin
from core.utils import text_

logger = logging.getLogger(__name__)


class CacheResponsesPlugin(HttpProxyBasePlugin):
    """Caches Upstream Server Responses."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection) -> None:
        super().__init__(config, client)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        # Ideally should only create file if upstream connection succeeds.
        self.cache_file_path = os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (text_(request.host), str(time.time())))
        self.cache_file = open(self.cache_file_path, "wb")
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self,
                              chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
        logger.info('Cached response at %s', self.cache_file_path)
