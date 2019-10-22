# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from .http_parser import HttpParser


class ProtocolException(Exception):
    """Top level ProtocolException exception class.

    All exceptions raised during execution of Http request lifecycle MUST
    inherit ProtocolException base class. Implement response() method
    to optionally return custom response to client."""

    def response(self, request: HttpParser) -> Optional[bytes]:
        return None  # pragma: no cover
