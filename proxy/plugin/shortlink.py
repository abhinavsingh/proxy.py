# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       shortlink
"""
from typing import Optional

from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser
from ..http.responses import NOT_FOUND_RESPONSE_PKT, seeOthersResponse
from ..common.constants import DOT, SLASH


class ShortLinkPlugin(HttpProxyBasePlugin):
    """Add support for short links in your favorite browsers / applications.

    Enable ShortLinkPlugin and speed up your daily browsing experience.

    Example::
    * ``f/`` for ``facebook.com``
    * ``g/`` for ``google.com`
    * ``t/`` for ``twitter.com``
    * ``y/`` for ``youtube.com``
    * ``proxy/`` for ``py`` internal web servers.
    Customize map below for your taste and need.

    Paths are also preserved. E.g. ``t/imoracle`` will
    resolve to http://twitter.com/imoracle.
    """

    SHORT_LINKS = {
        b'a': b'amazon.com',
        b'i': b'instagram.com',
        b'l': b'linkedin.com',
        b'f': b'facebook.com',
        b'g': b'google.com',
        b't': b'twitter.com',
        b'w': b'web.whatsapp.com',
        b'y': b'youtube.com',
        b'proxy': b'localhost:8899',
    }

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.host and request.host != b'localhost' and DOT not in request.host:
            # Avoid connecting to upstream
            return None
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.host and request.host != b'localhost' and DOT not in request.host:
            if request.host in self.SHORT_LINKS:
                path = SLASH if not request.path else request.path
                self.client.queue(
                    seeOthersResponse(
                        b'http://' + self.SHORT_LINKS[request.host] + path,
                    ),
                )
            else:
                self.client.queue(NOT_FOUND_RESPONSE_PKT)
            return None
        return request
