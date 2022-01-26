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
import multiprocessing
from typing import Any, Dict, Optional

from .base import BaseCacheResponsesPlugin
from .store.disk import OnDiskCacheStore
from ...http.parser import HttpParser, httpParserTypes
from ...common.constants import SLASH


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
            self.write_content_type(
                self.disk_store.cache_file_path,
                self.disk_store.cache_dir,
                self.disk_store.cache_file_name,
                self.flags.cache_requests,
            )

    @staticmethod
    def write_content_type(
            cache_file_path: str,
            content_dir: str,
            content_file_name: str,
            cache_requests: bool,
    ) -> Optional[str]:
        if not cache_requests:
            parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
            with open(cache_file_path, 'rb') as cache:
                data = cache.read()
                parser.parse(memoryview(data))
            assert parser.is_complete
            if parser.body_expected:
                assert parser.body
                content_type = parser.header(b'content-type') \
                    if parser.has_header(b'content-type') \
                    else b'text/plain'
                extension = content_type.split(SLASH)[-1].decode('utf-8')
                content_file_path = os.path.join(
                    content_dir,
                    '%s.%s' % (content_file_name, extension),
                )
                with open(content_file_path, 'wb') as content:
                    content.write(parser.body)
                logger.info('Cached content file at %s', content_file_path)
                return content_file_path
        else:
            # Last dumped packet is likely the response
            # packet
            pass
        return None
