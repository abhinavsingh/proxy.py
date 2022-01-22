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
from typing import Any, Dict, Optional

from ..http.proxy import HttpProxyBasePlugin
from ..common.utils import tls_interception_enabled


logger = logging.getLogger(__name__)


class CacheByContentTypePlugin(HttpProxyBasePlugin):
    """This plugin is supposed to work with
    :py:class`~proxy.plugin.cache.CacheResponsesPlugin`.  This plugin
    must be put after the cache response plugin in the chain.

    Plugin will try to extract out content type from the responses.
    When found, data is stored under ``proxy.py`` instance data directory."""

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if tls_interception_enabled(self.flags) and 'cache_file_path' in context:
            print('cache file found')
        return super().on_access_log(context)
