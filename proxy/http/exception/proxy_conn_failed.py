# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       conn
"""
from typing import TYPE_CHECKING, Any

from proxy.http.responses import BAD_GATEWAY_RESPONSE_PKT
from proxy.http.exception.base import HttpProtocolException


if TYPE_CHECKING:   # pragma: no cover
    from ..parser import HttpParser


class ProxyConnectionFailed(HttpProtocolException):
    """Exception raised when ``HttpProxyPlugin`` is unable to establish connection to upstream server."""

    def __init__(self, host: str, port: int, reason: str, **kwargs: Any):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason
        super().__init__('%s %s' % (self.__class__.__name__, reason), **kwargs)

    def response(self, _request: 'HttpParser') -> memoryview:
        return BAD_GATEWAY_RESPONSE_PKT
