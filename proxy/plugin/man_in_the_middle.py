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
from ..common.utils import build_http_response
from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin


class ManInTheMiddlePlugin(HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return memoryview(
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK',
                body=b'Hello from man in the middle',
            ),
        )
