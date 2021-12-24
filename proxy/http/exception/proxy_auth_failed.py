# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       auth
       http
"""
from typing import TYPE_CHECKING, Any

from .base import HttpProtocolException

from ..responses import PROXY_AUTH_FAILED_RESPONSE_PKT

if TYPE_CHECKING:
    from ..parser import HttpParser


class ProxyAuthenticationFailed(HttpProtocolException):
    """Exception raised when HTTP Proxy auth is enabled and
    incoming request doesn't present necessary credentials."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(self.__class__.__name__, **kwargs)

    def response(self, _request: 'HttpParser') -> memoryview:
        return PROXY_AUTH_FAILED_RESPONSE_PKT
