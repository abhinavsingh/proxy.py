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
import logging
from typing import BinaryIO, Optional

from .base import CacheStore
from ....common.flag import flags
from ....http.parser import HttpParser
from ....common.utils import text_
from ....common.constants import DEFAULT_CACHE_DIRECTORY_PATH


logger = logging.getLogger(__name__)


flags.add_argument(
    '--cache-dir',
    type=str,
    default=DEFAULT_CACHE_DIRECTORY_PATH,
    help='Default: ' + DEFAULT_CACHE_DIRECTORY_PATH + '.  ' +
    'Flag only applicable when cache plugin is used with on-disk storage.',
)


class OnDiskCacheStore(CacheStore):

    def __init__(self, uid: str, cache_dir: str, cache_requests: bool) -> None:
        super().__init__(uid)
        self.cache_dir = cache_dir
        self.cache_requests = cache_requests
        self.cache_file_name: Optional[str] = None
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def open(self, request: HttpParser) -> None:
        self.cache_file_name = '%s-%s' % (text_(request.host), self.uid)
        self.cache_file_path = os.path.join(
            self.cache_dir,
            '%s.txt' % self.cache_file_name,
        )
        self.cache_file = open(self.cache_file_path, "wb")

    def cache_request(self, request: HttpParser) -> Optional[HttpParser]:
        if self.cache_file and self.cache_requests:
            self.cache_file.write(request.build())
        return request

    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        if self.cache_file:
            self.cache_file.write(chunk.tobytes())
        return chunk

    def close(self) -> None:
        if self.cache_file:
            self.cache_file.flush()
            self.cache_file.close()
            self.cache_file = None
            logger.info('Cached response at %s', self.cache_file_path)
