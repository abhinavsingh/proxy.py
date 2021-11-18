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
from typing import Optional

from ..parser import HttpParser


class HttpProtocolException(Exception):
    """Top level :exc:`HttpProtocolException` exception class.

    All exceptions raised during execution of HTTP request lifecycle MUST
    inherit :exc:`HttpProtocolException` base class. Implement
    ``response()`` method to optionally return custom response to client.
    """

    def response(self, request: HttpParser) -> Optional[memoryview]:
        return None  # pragma: no cover
