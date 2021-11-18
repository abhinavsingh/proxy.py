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
from urllib import parse as urlparse
from typing import Optional

from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser
from ..common.utils import bytes_
from ..common.constants import DEFAULT_PORT


class RedirectToCustomServerPlugin(HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = bytes_('http://localhost:{0}/'.format(DEFAULT_PORT))

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        # Redirect all non-https requests to inbuilt WebServer.
        if not request.is_https_tunnel():
            request.set_url(self.UPSTREAM_SERVER)
            # Update Host header too, otherwise upstream can reject our request
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(
                b'Host', urlparse.urlsplit(
                    self.UPSTREAM_SERVER,
                ).netloc,
            )
        return request
