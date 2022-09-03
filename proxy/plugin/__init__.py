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
       ws
       onmessage
       httpbin
       localhost
       Lua
"""
from proxy.plugin.cache import CacheResponsesPlugin, BaseCacheResponsesPlugin
from proxy.plugin.shortlink import ShortLinkPlugin
from proxy.plugin.proxy_pool import ProxyPoolPlugin
from proxy.plugin.program_name import ProgramNamePlugin
from proxy.plugin.mock_rest_api import ProposedRestApiPlugin
from proxy.plugin.reverse_proxy import ReverseProxyPlugin
from proxy.plugin.cloudflare_dns import CloudflareDnsResolverPlugin
from proxy.plugin.modify_post_data import ModifyPostDataPlugin
from proxy.plugin.web_server_route import WebServerPlugin
from proxy.plugin.man_in_the_middle import ManInTheMiddlePlugin
from proxy.plugin.filter_by_upstream import FilterByUpstreamHostPlugin
from proxy.plugin.custom_dns_resolver import CustomDnsResolverPlugin
from proxy.plugin.filter_by_client_ip import FilterByClientIpPlugin
from proxy.plugin.filter_by_url_regex import FilterByURLRegexPlugin
from proxy.plugin.modify_chunk_response import ModifyChunkResponsePlugin
from proxy.plugin.redirect_to_custom_server import RedirectToCustomServerPlugin


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
