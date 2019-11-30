# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from .cache import CacheResponsesPlugin, BaseCacheResponsesPlugin
from .filter_by_upstream import FilterByUpstreamHostPlugin
from .man_in_the_middle import ManInTheMiddlePlugin
from .mock_rest_api import ProposedRestApiPlugin
from .modify_post_data import ModifyPostDataPlugin
from .redirect_to_custom_server import RedirectToCustomServerPlugin
from .shortlink import ShortLinkPlugin
from .web_server_route import WebServerPlugin
from .reverse_proxy import ReverseProxyPlugin

__all__ = [
    'CacheResponsesPlugin',
    'BaseCacheResponsesPlugin',
    'FilterByUpstreamHostPlugin',
    'ManInTheMiddlePlugin',
    'ProposedRestApiPlugin',
    'ModifyPostDataPlugin',
    'RedirectToCustomServerPlugin',
    'ShortLinkPlugin',
    'WebServerPlugin',
    'ReverseProxyPlugin',
]
