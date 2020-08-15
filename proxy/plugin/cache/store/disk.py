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
from hashlib import sha512
from uuid import UUID

from ....common.utils import text_
from ....http.parser import HttpParser

from .base import CacheStore

logger = logging.getLogger(__name__)


class OnDiskCacheStore(CacheStore):

    def __init__(self, uid: UUID, cache_dir: str) -> None:
        super().__init__(uid)
        self.cache_dir = cache_dir
        if not os.path.isdir(self.cache_dir):
            os.mkdir(self.cache_dir)
        logger.debug("Opening cache list")
        self.cache_list = open(os.path.join(self.cache_dir, 'list.txt'), 'at')
        self.cache_file: Optional[BinaryIO] = None

    def __del__(self) -> None:
        logger.debug("Closing cache list")
        self.cache_list.close()

    def open(self, request: HttpParser) -> None:
        pass

    def cache_request(self, request: HttpParser) -> Optional[HttpParser]:
        body_hash = sha512(request.body).hexdigest() if request.body else 'None'
        cache_file_name = '%s-%s.txt' % (text_(request.host), self.uid.hex)
        self.cache_list.write('%s %s %s %s %s\n' % (
            request.method.decode() if request.method else 'None',
            request.host.decode() if request.host else 'None',
            request.path.decode() if request.path else 'None',
            body_hash,
            cache_file_name
        ))

        if self.cache_file:
            self.cache_file.close()
        self.cache_file = open(os.path.join(self.cache_dir, cache_file_name), "ab")
        return request

    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        if self.cache_file:
            self.cache_file.write(chunk.tobytes())
        return chunk

    def close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
