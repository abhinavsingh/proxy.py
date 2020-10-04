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
        pass

    @abstractmethod
    def is_cached(self, request: HttpParser) -> bool:
        """Returns whether the request is already cached."""
        pass

    @abstractmethod
    def cache_request(self, request: HttpParser) -> HttpParser:
        """Cache the request."""
        return request

    @abstractmethod
    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        """Cache response chunks as they arrive."""
        return chunk

    @abstractmethod
    def close(self) -> None:
        """Close any open resources."""
        pass
