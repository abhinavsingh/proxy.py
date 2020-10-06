# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Any

from examples.base_server import BaseServerHandler


class BaseEchoServerHandler(BaseServerHandler):     # type: ignore
    """BaseEchoServerHandler implements BaseServerHandler interface.

    An instance of BaseServerHandler is created for each client
    connection.  BaseServerHandler lifecycle is controlled by
    Threadless core using asyncio.

    Implementation must provide:
    a) handle_data(data: memoryview)
    c) (optionally) intialize, is_inactive and shutdown methods
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def handle_data(self, data: memoryview) -> None:
        self.client.queue(data)
