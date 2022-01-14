# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import Optional, Any

from ...http.parser import HttpParser
from ...http.proxy import HttpProxyBasePlugin
from .store.base import CacheStore

logger = logging.getLogger(__name__)


class BaseCacheResponsesPlugin(HttpProxyBasePlugin):
    """Base cache plugin.

    It requires a storage backend to work with. Storage class
    must implement CacheStore interface.

    Different storage backends can be used per request if required.
    """

    def __init__(
            self,
            *args: Any,
            **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.store: Optional[CacheStore] = None

    def set_store(self, store: CacheStore) -> None:
        self.store = store

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        assert self.store
        try:
            self.store.open(request)
        except Exception as e:
            logger.info('Caching disabled due to exception message %s', str(e))
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        assert self.store
        return self.store.cache_request(request)

    def handle_upstream_chunk(self, chunk: memoryview) -> Optional[memoryview]:
        assert self.store
        return self.store.cache_response_chunk(chunk)

    def on_upstream_connection_close(self) -> None:
        assert self.store
        self.store.close()
