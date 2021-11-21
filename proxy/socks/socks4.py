# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any, Optional

from ..core.base import BaseTcpServerHandler


class Socks4ProtocolHandler(BaseTcpServerHandler):
    """Reference https://www.openssh.com/txt/socks4.protocol"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def handle_data(self, data: memoryview) -> Optional[bool]:
        return super().handle_data(data)
