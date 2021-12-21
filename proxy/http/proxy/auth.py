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
from typing import Optional

from ..exception import ProxyAuthenticationFailed

from ...common.flag import flags
from ...common.constants import DEFAULT_BASIC_AUTH

from ...http import httpHeaders
from ...http.parser import HttpParser
from ...http.proxy import HttpProxyBasePlugin


flags.add_argument(
    '--basic-auth',
    type=str,
    default=DEFAULT_BASIC_AUTH,
    help='Default: No authentication. Specify colon separated user:password '
    'to enable basic authentication.',
)


class AuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if self.flags.auth_code and request.headers:
            if httpHeaders.PROXY_AUTHORIZATION not in request.headers:
                raise ProxyAuthenticationFailed()
            parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
            if len(parts) != 2 \
                    or parts[0].lower() != b'basic' \
                    or parts[1] != self.flags.auth_code:
                raise ProxyAuthenticationFailed()
        return request
