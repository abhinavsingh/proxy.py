# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import multiprocessing
from typing import Any

from .store.disk import OnDiskCacheStore
from .base import BaseCacheResponsesPlugin


class CacheResponsesPlugin(BaseCacheResponsesPlugin):
    """Caches response using OnDiskCacheStore."""

    # Dynamically enable / disable cache
    ENABLED = multiprocessing.Event()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.disk_store = OnDiskCacheStore(
            uid=self.uid, cache_dir=self.flags.cache_dir)
        self.set_store(self.disk_store)
