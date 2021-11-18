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

       http
       Submodules
"""
from .parser import HttpParser
from .chunk import ChunkParser, chunkParserStates
from .types import httpParserStates, httpParserTypes
from .protocol import ProxyProtocol, PROXY_PROTOCOL_V2_SIGNATURE

__all__ = [
    'HttpParser',
    'httpParserTypes',
    'httpParserStates',
    'ChunkParser',
    'chunkParserStates',
    'ProxyProtocol',
    'PROXY_PROTOCOL_V2_SIGNATURE',
]
