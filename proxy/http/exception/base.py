# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       http
"""
from typing import TYPE_CHECKING, Any, Optional


if TYPE_CHECKING:   # pragma: no cover
    from ..parser import HttpParser


class HttpProtocolException(Exception):
    """Top level :exc:`HttpProtocolException` exception class.

    All exceptions raised during execution of HTTP request lifecycle MUST
    inherit :exc:`HttpProtocolException` base class. Implement
    ``response()`` method to optionally return custom response to client.
    """

    def __init__(self, message: Optional[str] = None, **kwargs: Any) -> None:
        super().__init__(message or 'Reason unknown')

    def response(self, request: 'HttpParser') -> Optional[memoryview]:
        return None  # pragma: no cover
