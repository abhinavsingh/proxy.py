# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       http
"""
from typing import Optional, Dict

from .base import HttpProtocolException
from ..parser import HttpParser
from ...common.utils import build_http_response


class HttpRequestRejected(HttpProtocolException):
    """Generic exception that can be used to reject the client requests.

    Connections can either be dropped/closed or optionally an
    HTTP status code can be returned."""

    def __init__(
        self,
        status_code: Optional[int] = None,
        reason: Optional[bytes] = None,
        headers: Optional[Dict[bytes, bytes]] = None,
        body: Optional[bytes] = None,
    ):
        self.status_code: Optional[int] = status_code
        self.reason: Optional[bytes] = reason
        self.headers: Optional[Dict[bytes, bytes]] = headers
        self.body: Optional[bytes] = body

    def response(self, _request: HttpParser) -> Optional[memoryview]:
        if self.status_code:
            return memoryview(
                build_http_response(
                    status_code=self.status_code,
                    reason=self.reason,
                    headers=self.headers,
                    body=self.body,
                ),
            )
        return None
