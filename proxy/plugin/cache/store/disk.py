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
import tempfile
from typing import Optional, BinaryIO
from uuid import UUID

from ....common.flag import flags
from ....common.utils import text_
from ....http.parser import HttpParser

from .base import CacheStore

logger = logging.getLogger(__name__)


flags.add_argument(
    '--cache-dir',
    type=str,
    default=tempfile.gettempdir(),
    help='Default: A temporary directory.  Flag only applicable when cache plugin is used with on-disk storage.'
)


class OnDiskCacheStore(CacheStore):

    def __init__(self, uid: UUID, cache_dir: str) -> None:
        super().__init__(uid)
        self.cache_dir = cache_dir
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def open(self, request: HttpParser) -> None:
        self.cache_file_path = os.path.join(
            self.cache_dir,
            '%s-%s.txt' % (text_(request.host), self.uid.hex))
        self.cache_file = open(self.cache_file_path, "wb")

    def cache_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        if self.cache_file:
            self.cache_file.write(chunk.tobytes())
        return chunk

    def close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
            logger.info('Cached response at %s', self.cache_file_path)
