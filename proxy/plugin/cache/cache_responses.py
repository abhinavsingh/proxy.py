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
from typing import Any

from .store.disk import OnDiskCacheStore
from .base import BaseCacheResponsesPlugin


class CacheResponsesPlugin(BaseCacheResponsesPlugin):
    """Pluggable caches response plugin.

    Defaults to OnDiskCacheStore.

    Different storage backends may be used per request if required.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.disk_store = OnDiskCacheStore(
            uid=self.uid, cache_dir=self.cache_directory())
        self.set_store(self.disk_store)

    def cache_directory(self) -> str:
        """TODO(abhinavsingh): Turn this into a flag."""
        return os.path.join(self.flags.proxy_py_data_dir, 'cache')
