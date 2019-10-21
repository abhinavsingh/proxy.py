# -*- coding: utf-8 -*-
"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from core.http_proxy import HttpProxyBasePlugin
from core.http_parser import HttpParser
from core.status_codes import httpStatusCodes
from core.constants import DOT
from core.utils import build_http_response


class ShortLinkPlugin(HttpProxyBasePlugin):
    """Add support for short links in your favorite browsers / applications.

    Enable ShortLinkPlugin and speed up your daily browsing experience.

    Example:
    * f/ for facebook.com
    * g/ for google.com
    * t/ for twitter.com
    * y/ for youtube.com
    * proxy/ for py internal web servers.
    Customize map below for your taste and need.

    Paths are also preserved. E.g. t/imoracle will
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

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        if request.host and request.host != b'localhost' and DOT not in request.host:
            # Avoid connecting to upstream
            return None
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        if request.host and request.host != b'localhost' and DOT not in request.host:
            if request.host in self.SHORT_LINKS:
                path = SLASH if not request.path else request.path
                self.client.queue(build_http_response(
                    httpStatusCodes.SEE_OTHER, reason=b'See Other',
                    headers={
                        b'Location': b'http://' + self.SHORT_LINKS[request.host] + path,
                        b'Content-Length': b'0',
                        b'Connection': b'close',
                    }
                ))
            else:
                self.client.queue(build_http_response(
                    httpStatusCodes.NOT_FOUND, reason=b'NOT FOUND',
                    headers={
                        b'Content-Length': b'0',
                        b'Connection': b'close',
                    }
                ))
            return None
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
