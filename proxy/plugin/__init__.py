# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       Cloudflare
       ws
       onmessage
       httpbin
       localhost
       Lua
"""
from .cache import CacheResponsesPlugin, BaseCacheResponsesPlugin
from .shortlink import ShortLinkPlugin
from .proxy_pool import ProxyPoolPlugin
from .program_name import ProgramNamePlugin
from .mock_rest_api import ProposedRestApiPlugin
from .reverse_proxy import ReverseProxyPlugin
from .cloudflare_dns import CloudflareDnsResolverPlugin
from .modify_post_data import ModifyPostDataPlugin
from .web_server_route import WebServerPlugin
from .man_in_the_middle import ManInTheMiddlePlugin
from .filter_by_upstream import FilterByUpstreamHostPlugin
from .custom_dns_resolver import CustomDnsResolverPlugin
from .filter_by_client_ip import FilterByClientIpPlugin
from .filter_by_url_regex import FilterByURLRegexPlugin
from .modify_chunk_response import ModifyChunkResponsePlugin
from .redirect_to_custom_server import RedirectToCustomServerPlugin


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
    'ProgramNamePlugin',
]
