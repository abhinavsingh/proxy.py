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
import gzip
import logging
import multiprocessing
from typing import Any, Dict, Optional

from .base import BaseCacheResponsesPlugin
from ...http import httpStatusCodes
from .store.disk import OnDiskCacheStore
from ...http.parser import HttpParser, httpParserTypes
from ...common.constants import SLASH


br_installed = False
try:
    import brotli
    br_installed = True
except ModuleNotFoundError:
    pass

logger = logging.getLogger(__name__)


class CacheResponsesPlugin(BaseCacheResponsesPlugin):
    """Caches response using OnDiskCacheStore."""

    # Dynamically enable / disable cache
    ENABLED = multiprocessing.Event()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.disk_store = OnDiskCacheStore(
            uid=self.uid,
            cache_dir=os.path.join(
                self.flags.cache_dir,
                'responses',
            ),
            cache_requests=self.flags.cache_requests,
        )
        self.set_store(self.disk_store)

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        context.update({
            'cache_file_path': self.disk_store.cache_file_path,
        })
        return super().on_access_log(context)

    def on_upstream_connection_close(self) -> None:
        super().on_upstream_connection_close()
        if self.flags.cache_by_content_type and \
                self.disk_store.cache_file_path and \
                self.disk_store.cache_file_name:
            try:
                self.write_content_type(
                    self.disk_store.cache_file_path,
                    self.flags.cache_dir,
                    self.disk_store.cache_file_name,
                    self.flags.cache_requests,
                )
            except Exception as e:
                logger.exception('Unable to cache by content type', exc_info=e)

    @staticmethod
    def write_content_type(
            cache_file_path: str,
            cache_dir: str,
            content_file_name: str,
            cache_requests: bool,
    ) -> Optional[str]:
        if not cache_requests:
            parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
            with open(cache_file_path, 'rb') as cache:
                data = cache.read()
                parser.parse(memoryview(data))
            if parser.code and int(parser.code) == httpStatusCodes.SWITCHING_PROTOCOLS:
                logger.warning('Bypassing websocket response packet')
                return None
            # if not parser.is_complete:
            #     logger.warning(data)
            #     return None
            if parser.body_expected and parser.body:
                body = parser.body
                if parser.has_header(b'content-encoding'):
                    encoding = parser.header(b'content-encoding')
                    if encoding == b'gzip':
                        body = gzip.decompress(body)
                    elif encoding == b'br' and br_installed:
                        body = brotli.decompress(body)
                    else:
                        logger.warning(
                            'Unsupported content encoding %s',
                            encoding,
                        )
                        return None
                content_type = parser.header(b'content-type') \
                    if parser.has_header(b'content-type') \
                    else b'text/plain'
                extension = content_type.split(
                    SLASH, maxsplit=1,
                )[-1].split(b';', maxsplit=1)[0].split(b'+', maxsplit=1)[0].decode('utf-8')
                content_file_path = os.path.join(
                    cache_dir, 'content',
                    '%s.%s' % (content_file_name, extension),
                )
                with open(content_file_path, 'wb') as content:
                    content.write(body)
                logger.info('Cached content file at %s', content_file_path)
                return content_file_path
        else:
            # Last dumped packet is likely the response
            # packet
            pass
        return None
