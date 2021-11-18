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
"""
from typing import Optional

from ..parser import HttpParser


class HttpProtocolException(Exception):
    """Top level :exc:`HttpProtocolException` exception class.

    All exceptions raised during execution of HTTP request lifecycle MUST
    inherit :exc:`HttpProtocolException` base class. Implement
    ``response()`` method to optionally return custom response to client.
    """

    def response(self, request: HttpParser) -> Optional[memoryview]:
        return None  # pragma: no cover
