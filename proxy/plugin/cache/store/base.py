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
from typing import Optional

from ....http.parser import HttpParser


class CacheStore(ABC):

    def __init__(self, uid: str) -> None:
        self.uid = uid

    @abstractmethod
    def open(self, request: HttpParser) -> None:
        pass

    @abstractmethod
    def cache_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    @abstractmethod
    def cache_response_chunk(self, chunk: bytes) -> bytes:
        return chunk

    @abstractmethod
    def close(self) -> None:
        pass
