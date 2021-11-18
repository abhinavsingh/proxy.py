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

       conn
       http
"""
from .base import HttpProtocolException

from ..codes import httpStatusCodes
from ..parser import HttpParser

from ...common.constants import PROXY_AGENT_HEADER_VALUE, PROXY_AGENT_HEADER_KEY
from ...common.utils import build_http_response


class ProxyConnectionFailed(HttpProtocolException):
    """Exception raised when ``HttpProxyPlugin`` is unable to establish connection to upstream server."""

    RESPONSE_PKT = memoryview(
        build_http_response(
            httpStatusCodes.BAD_GATEWAY,
            reason=b'Bad Gateway',
            headers={
                PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
                b'Connection': b'close',
            },
            body=b'Bad Gateway',
        ),
    )

    def __init__(self, host: str, port: int, reason: str):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason

    def response(self, _request: HttpParser) -> memoryview:
        return self.RESPONSE_PKT
