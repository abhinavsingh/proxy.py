# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from proxy.http.exception.base import HttpProtocolException
from proxy.http.exception.proxy_auth_failed import ProxyAuthenticationFailed
from proxy.http.exception.proxy_conn_failed import ProxyConnectionFailed
from proxy.http.exception.http_request_rejected import HttpRequestRejected


__all__ = [
    'HttpProtocolException',
    'HttpRequestRejected',
    'ProxyAuthenticationFailed',
    'ProxyConnectionFailed',
]
