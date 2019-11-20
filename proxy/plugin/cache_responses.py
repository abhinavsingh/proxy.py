# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import tempfile
import logging
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO, Any

from ..common.utils import text_
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin

logger = logging.getLogger(__name__)


class BaseCacheResponsesPlugin(HttpProxyBasePlugin, ABC):
    """Base cache plugin."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(
            self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        self.cache_file_path = self.get_cache_file_path(request)
        self.cache_file = open(self.cache_file_path, "wb")
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(
            self,
            chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
        logger.info('Cached response at %s', self.cache_file_path)

    @abstractmethod
    def get_cache_file_path(self, request: HttpParser) -> str:
        """Override for customizing cache paths."""
        raise NotImplementedError()


class CacheResponsesPlugin(BaseCacheResponsesPlugin):
    """Customizes response cache path to /tmp/hostname-unique_request_id."""

    def get_cache_file_path(self, request: HttpParser) -> str:
        return os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (text_(request.host), self.uid))
