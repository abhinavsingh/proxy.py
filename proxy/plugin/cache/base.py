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
from proxy.common.constants import CRLF
from typing import Optional, Any

from .store.base import CacheStore
from ...http.parser import HttpParser
from ...http.proxy import HttpProxyBasePlugin

logger = logging.getLogger(__name__)


class BaseCacheResponsesPlugin(HttpProxyBasePlugin):
    """Base cache plugin.

    Cache plugin requires a storage backend to work with.
    Storage class must implement this interface.
    """

    def __init__(
            self,
            *args: Any,
            **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store: Optional[CacheStore] = None

        # Multiple requests can flow over a single connection.
        # Example, CONNECT followed by one or many HTTP requests.
        #
        # Scheme is stored as attribute as request
        # object is not available across all lifecycle
        # callbacks.
        self.scheme: bytes = b'http'

    def set_store(self, store: CacheStore) -> None:
        self.store = store

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Avoid connection with upstream server if cached response exists.

        Disabled for https request when running without TLS interception.
        """
        assert request.url is not None

        # Store request scheme
        self.scheme = request.url.scheme

        # Cache plugin is enabled for HTTPS request only when
        # TLS interception is also enabled.
        if self.scheme == b'https' and not self.tls_interception_enabled():
            return request

        # Cache plugin is a no-op for CONNECT requests
        # i.e. we don't cache CONNECT responses.  However,
        # we do skip upstream connection
        #
        # See https://github.com/abhinavsingh/proxy.py/issues/443
        # if request.method == b'CONNECT':
        #     return None

        assert self.store
        if self.store.is_cached(request):
            return None
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        """If cached response exists, return response from cache."""
        assert request.url is not None

        # Cache plugin is enabled for HTTPS request only when
        # TLS interception is also enabled.
        if request.url.scheme == b'https' and not self.tls_interception_enabled():
            return request

        assert self.store
        if self.store.is_cached(request):
            logger.info("Serving out of cache")
            try:
                self.store.open(request)
                response = self.store.read_response(request)
                self.client.queue(memoryview(response.build_response()))
            finally:
                self.store.close()
            return None
        # Request not cached, open store for writes
        self.store.open(request)
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        if self.scheme == b'https' and not self.tls_interception_enabled():
            return chunk

        assert self.store
        chunk = self.store.cache_response_chunk(chunk)
        if chunk.tobytes().endswith(CRLF * 2):
            self.store.close()
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.scheme == b'https' and not self.tls_interception_enabled():
            return

        assert self.store
        self.store.close()

    def tls_interception_enabled(self) -> bool:
        return self.flags.ca_key_file is not None and \
            self.flags.ca_cert_dir is not None and \
            self.flags.ca_signing_key_file is not None and \
            self.flags.ca_cert_file is not None
