# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import ABC, abstractmethod
from uuid import UUID
from ....http.parser import HttpParser


class CacheStore(ABC):
    """Cache storage backends must implement this interface."""

    def __init__(self, uid: UUID) -> None:
        self.uid = uid

    @abstractmethod
    def open(self, request: HttpParser) -> None:
        """Initialize resources to handle this request."""
        pass    # pragma: no cover

    @abstractmethod
    def is_cached(self, request: HttpParser) -> bool:
        """Returns whether the request is already cached."""
        pass    # pragma: no cover

    @abstractmethod
    def cache_request(self, request: HttpParser) -> HttpParser:
        """Cache the request."""
        return request  # pragma: no cover

    @abstractmethod
    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        """Cache response chunks as they arrive."""
        return chunk    # pragma: no cover

    @abstractmethod
    def read_response(self, request: HttpParser) -> HttpParser:
        """Reads and return cached response from store."""
        pass    # pragma: no cover

    @abstractmethod
    def close(self) -> None:
        """Close any open resources."""
        pass    # pragma: no cover
