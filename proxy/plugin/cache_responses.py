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

from ..common.utils import text_
from ..http.parser import HttpParser

from .cache_responses_base import BaseCacheResponsesPlugin


class CacheResponsesPlugin(BaseCacheResponsesPlugin):
    """Customizes response cache path to /tmp/hostname-unique_request_id."""

    def get_cache_file_path(self, request: HttpParser) -> str:
        return os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (text_(request.host), self.uid))
