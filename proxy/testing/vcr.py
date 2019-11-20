# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import multiprocessing
import os

from ..common.utils import text_
from ..http.parser import HttpParser
from ..plugin import BaseCacheResponsesPlugin


class VCRPlugin(BaseCacheResponsesPlugin):

    ENABLED = multiprocessing.Event()

    def get_cache_file_path(self, request: HttpParser) -> str:
        if not VCRPlugin.ENABLED.is_set():
            raise Exception('VCR not enabled')
        return os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (text_(request.host), self.uid))
