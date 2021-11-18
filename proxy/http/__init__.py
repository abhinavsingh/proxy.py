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
       Subpackages
       Submodules
"""
from .handler import HttpProtocolHandler
from .plugin import HttpProtocolHandlerPlugin
from .codes import httpStatusCodes
from .methods import httpMethods
from .url import Url

__all__ = [
    'HttpProtocolHandler',
    'HttpProtocolHandlerPlugin',
    'httpStatusCodes',
    'httpMethods',
    'Url',
]
