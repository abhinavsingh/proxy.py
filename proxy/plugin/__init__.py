# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       Cloudflare
       Submodules
"""
from .cache import BaseCacheResponsesPlugin, CacheResponsesPlugin
from .cloudflare_dns import CloudflareDnsResolverPlugin
from .custom_dns_resolver import CustomDnsResolverPlugin
from .filter_by_client_ip import FilterByClientIpPlugin
from .filter_by_upstream import FilterByUpstreamHostPlugin
from .filter_by_url_regex import FilterByURLRegexPlugin
from .man_in_the_middle import ManInTheMiddlePlugin
from .mock_rest_api import ProposedRestApiPlugin
from .modify_chunk_response import ModifyChunkResponsePlugin
from .modify_post_data import ModifyPostDataPlugin
from .proxy_pool import ProxyPoolPlugin
from .redirect_to_custom_server import RedirectToCustomServerPlugin
from .reverse_proxy import ReverseProxyPlugin
from .shortlink import ShortLinkPlugin
from .web_server_route import WebServerPlugin


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
    'ProxyPoolPlugin',
    'FilterByClientIpPlugin',
    'ModifyChunkResponsePlugin',
    'FilterByURLRegexPlugin',
    'CustomDnsResolverPlugin',
    'CloudflareDnsResolverPlugin',
]
