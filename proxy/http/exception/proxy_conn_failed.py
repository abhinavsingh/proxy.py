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
from typing import TYPE_CHECKING

from .base import HttpProtocolException

from ..codes import httpStatusCodes

if TYPE_CHECKING:
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
            },
            body=b'Bad Gateway',
            conn_close=True,
        ),
    )

    def __init__(self, host: str, port: int, reason: str):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason

    def response(self, _request: 'HttpParser') -> memoryview:
        return self.RESPONSE_PKT
