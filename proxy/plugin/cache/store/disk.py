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
import os
from typing import Optional, BinaryIO
from uuid import UUID

from ....http.parser import HttpParser

from .base import CacheStore

logger = logging.getLogger(__name__)


class OnDiskCacheStore(CacheStore):

    def __init__(self, uid: UUID, cache_dir: str) -> None:
        super().__init__(uid)
        self.cache_dir = cache_dir
        if not os.path.isdir(self.cache_dir):
            os.mkdir(self.cache_dir)
        self.cache_file: Optional[BinaryIO] = None

    def open(self, request: HttpParser) -> None:
        if not self.cache_file:
            cache_file_path = self.get_cache_file_path(request)
            logger.info('Opening cache file ' + cache_file_path)
            self.cache_file = open(cache_file_path, 'ab+')

    def is_cached(self, request: HttpParser) -> bool:
        return os.path.isfile(self.get_cache_file_path(request))

    def cache_request(self, request: HttpParser) -> HttpParser:
        return request

    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        assert self.cache_file is not None
        self.cache_file.write(chunk.tobytes())
        return chunk

    def read_response(self, request: HttpParser) -> HttpParser:
        assert self.cache_file is not None
        self.cache_file.seek(0)
        return HttpParser.response(self.cache_file.read())

    def close(self) -> None:
        if self.cache_file:
            logger.info('Closing cache file')
            self.cache_file.flush()
            self.cache_file.close()
            self.cache_file = None

    def get_cache_file_path(self, request: HttpParser) -> str:
        return os.path.join(self.cache_dir, '.'.join(
            [request.fingerprint(), 'cache']))
