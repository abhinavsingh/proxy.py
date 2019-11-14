# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import List, Tuple, Any

from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes


class DevtoolsProtocolPlugin(HttpWebServerBasePlugin):
    """Speaks DevTools protocol with client over websocket."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.WEBSOCKET, self.flags.devtools_ws_path)
        ]

    def handle_request(self, request: HttpParser) -> None:
        raise NotImplementedError('This should have never been called')

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_websocket_close(self) -> None:
        pass
