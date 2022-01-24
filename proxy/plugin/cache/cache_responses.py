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
import multiprocessing
from typing import Any, Dict, Optional

from .base import BaseCacheResponsesPlugin
from .store.disk import OnDiskCacheStore


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
