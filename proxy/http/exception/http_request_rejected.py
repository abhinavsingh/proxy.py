# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import TYPE_CHECKING, Any, Dict, Optional

from .base import HttpProtocolException
from ...common.utils import build_http_response


if TYPE_CHECKING:
    from ..parser import HttpParser


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
            **kwargs: Any,
    ):
        self.status_code: Optional[int] = status_code
        self.reason: Optional[bytes] = reason
        self.headers: Optional[Dict[bytes, bytes]] = headers
        self.body: Optional[bytes] = body
        klass_name = self.__class__.__name__
        super().__init__(
            message='%s %r' % (klass_name, reason)
            if reason
            else klass_name,
            **kwargs,
        )

    def response(self, _request: 'HttpParser') -> Optional[memoryview]:
        if self.status_code:
            return memoryview(
                build_http_response(
                    status_code=self.status_code,
                    reason=self.reason,
                    headers=self.headers,
                    body=self.body,
                    conn_close=True,
                ),
            )
        return None
