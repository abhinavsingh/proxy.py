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
import uuid
import multiprocessing
from typing import Optional, BinaryIO
from hashlib import sha512
from uuid import UUID

from ....common.utils import text_
from ....http.parser import HttpParser

from .base import CacheStore

logger = logging.getLogger(__name__)


class OnDiskCacheStore(CacheStore):

    # Used for file access synchronization
    lock = multiprocessing.Lock()

    def __init__(self, uid: UUID, cache_dir: str) -> None:
        super().__init__(uid)
        self.cache_dir = cache_dir
        if not os.path.isdir(self.cache_dir):
            os.mkdir(self.cache_dir)
        logger.debug("Opening cache list")
        self.cache_list = open(os.path.join(self.cache_dir, 'list.txt'), 'at')
        self.cache_file: Optional[BinaryIO] = None

    def __del__(self) -> None:
        if not self.cache_list.closed:
            self.cache_list.close()

    def open(self, request: HttpParser) -> None:
        pass

    def is_cached(self, request: HttpParser) -> bool:
        return bool(self.get_cache_file_path(request))

    def cache_request(self, request: HttpParser) -> HttpParser:
        cache_file_path = self.get_cache_file_path(request, True)
        if os.path.isfile(cache_file_path):
            logger.info('Found in cache file: %s' % cache_file_path)
            with open(cache_file_path, 'rb') as cache_file:
                return HttpParser.response(cache_file.read())

        if self.cache_file:
            logger.debug("Closing cache file")
            self.cache_file.close()
            self.cache_list.flush()
        logger.info('Caching in file: %s' % cache_file_path)
        self.cache_file = open(cache_file_path, "ab")
        return request

    def cache_response_chunk(self, chunk: memoryview) -> memoryview:
        if self.cache_file:
            self.cache_file.write(chunk.tobytes())
        return chunk

    def close(self) -> None:
        if self.cache_file:
            logger.debug("Closing cache file")
            self.cache_file.close()
            self.cache_list.flush()

    def get_cache_file_path(self, request: HttpParser,
                            create: bool = False) -> str:
        request_method = text_(request.method)
        request_host = text_(
            request.host if request.host else request.header(b'host'))
        request_path = text_(request.path)
        request_body = sha512(
            request.body).hexdigest() if request.body else 'None'

        with self.lock, open(os.path.join(self.cache_dir, 'list.txt'), 'rt') as cache_list:
            for cache_line in cache_list:
                method, host, path, body, cache_file_name = cache_line.strip().split(' ')
                if ((method == request_method) and (host == request_host) and
                        (path == request_path) and (body == request_body)):
                    return os.path.join(
                        self.cache_dir, 'proxy-cache-' + cache_file_name)

        if not create:
            return ''

        cache_file_name = uuid.uuid4().hex
        while os.path.isfile(os.path.join(self.cache_dir,
                                          'proxy-cache-' + cache_file_name)):
            cache_file_name = uuid.uuid4().hex

        with self.lock:
            self.cache_list.write('%s %s %s %s %s\n' % (
                request_method,
                request_host,
                request_path,
                request_body,
                cache_file_name
            ))
        return os.path.join(self.cache_dir, 'proxy-cache-' + cache_file_name)
