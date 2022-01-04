# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
# from .auth import AuthPlugin
from .plugin import HttpProxyBasePlugin
from .server import HttpProxyPlugin


__all__ = [
    'HttpProxyBasePlugin',
    'HttpProxyPlugin',
    # Causes circular import issues
    # because currently CacheResponsePlugin is always
    # loaded by default due to exposed TestCase class
    # at the top level.
    #
    # Due to multiple plugin imports during initiatization,
    # import of HttpProxyPluginBase results in circular
    # import issues.
    # 'AuthPlugin',
]
