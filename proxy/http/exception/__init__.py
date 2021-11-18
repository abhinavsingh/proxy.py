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
from .base import HttpProtocolException
from .http_request_rejected import HttpRequestRejected
from .proxy_auth_failed import ProxyAuthenticationFailed
from .proxy_conn_failed import ProxyConnectionFailed

__all__ = [
    'HttpProtocolException',
    'HttpRequestRejected',
    'ProxyAuthenticationFailed',
    'ProxyConnectionFailed',
]
