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
from .plugin import HttpProxyBasePlugin
from .server import HttpProxyPlugin
from .auth import AuthPlugin

__all__ = [
    'HttpProxyBasePlugin',
    'HttpProxyPlugin',
    'AuthPlugin',
]
