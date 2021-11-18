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
from typing import Optional

from ..common.utils import text_
from ..common.flag import flags

from ..http import httpStatusCodes
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin
from ..http.exception import HttpRequestRejected


flags.add_argument(
    '--filtered-upstream-hosts',
    type=str,
    default='facebook.com,www.facebook.com',
    help='Default: Blocks Facebook.  Comma separated list of IPv4 and IPv6 addresses.',
)


class FilterByUpstreamHostPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if text_(request.host) in self.flags.filtered_upstream_hosts.split(','):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close',
                },
            )
        return request
