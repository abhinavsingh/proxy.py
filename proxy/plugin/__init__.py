# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
"""
    .. spelling::

       Cloudflare
       Submodules
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
from .proxy_pool import ProxyPoolPlugin
from .filter_by_client_ip import FilterByClientIpPlugin
from .filter_by_url_regex import FilterByURLRegexPlugin
from .modify_chunk_response import ModifyChunkResponsePlugin
from .custom_dns_resolver import CustomDnsResolverPlugin
from .cloudflare_dns import CloudflareDnsResolverPlugin

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
