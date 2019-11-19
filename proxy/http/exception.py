# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional, Dict

from .parser import HttpParser
from .codes import httpStatusCodes

from ..common.constants import PROXY_AGENT_HEADER_VALUE, PROXY_AGENT_HEADER_KEY
from ..common.utils import build_http_response


class HttpProtocolException(Exception):
    """Top level HttpProtocolException exception class.

    All exceptions raised during execution of Http request lifecycle MUST
    inherit HttpProtocolException base class. Implement response() method
    to optionally return custom response to client."""

    def response(self, request: HttpParser) -> Optional[bytes]:
        return None  # pragma: no cover


class HttpRequestRejected(HttpProtocolException):
    """Generic exception that can be used to reject the client requests.

    Connections can either be dropped/closed or optionally an
    HTTP status code can be returned."""

    def __init__(self,
                 status_code: Optional[int] = None,
                 reason: Optional[bytes] = None,
                 headers: Optional[Dict[bytes, bytes]] = None,
                 body: Optional[bytes] = None):
        self.status_code: Optional[int] = status_code
        self.reason: Optional[bytes] = reason
        self.headers: Optional[Dict[bytes, bytes]] = headers
        self.body: Optional[bytes] = body

    def response(self, _request: HttpParser) -> Optional[bytes]:
        if self.status_code:
            return build_http_response(
                status_code=self.status_code,
                reason=self.reason,
                headers=self.headers,
                body=self.body
            )
        return None


class ProxyConnectionFailed(HttpProtocolException):
    """Exception raised when HttpProxyPlugin is unable to establish connection to upstream server."""

    RESPONSE_PKT = build_http_response(
        httpStatusCodes.BAD_GATEWAY,
        reason=b'Bad Gateway',
        headers={
            PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
            b'Connection': b'close'
        },
        body=b'Bad Gateway'
    )

    def __init__(self, host: str, port: int, reason: str):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT


class ProxyAuthenticationFailed(HttpProtocolException):
    """Exception raised when Http Proxy auth is enabled and
    incoming request doesn't present necessary credentials."""

    RESPONSE_PKT = build_http_response(
        httpStatusCodes.PROXY_AUTH_REQUIRED,
        reason=b'Proxy Authentication Required',
        headers={
            PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
            b'Proxy-Authenticate': b'Basic',
            b'Connection': b'close',
        },
        body=b'Proxy Authentication Required')

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT
