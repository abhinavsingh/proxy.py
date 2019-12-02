# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import gzip
from typing import List, Tuple, Optional, Any

from .plugin import HttpWebServerBasePlugin
from .protocols import httpProtocolTypes
from ..websocket import WebsocketFrame
from ..parser import HttpParser
from ...common.utils import bytes_, text_, build_http_response


class HttpWebServerPacFilePlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pac_file_response: Optional[memoryview] = None
        self.cache_pac_file_response()

    def routes(self) -> List[Tuple[int, str]]:
        if self.flags.pac_file_url_path:
            return [
                (httpProtocolTypes.HTTP, text_(self.flags.pac_file_url_path)),
                (httpProtocolTypes.HTTPS, text_(self.flags.pac_file_url_path)),
            ]
        return []   # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        if self.flags.pac_file and self.pac_file_response:
            self.client.queue(self.pac_file_response)

    def on_websocket_open(self) -> None:
        pass    # pragma: no cover

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass    # pragma: no cover

    def on_websocket_close(self) -> None:
        pass    # pragma: no cover

    def cache_pac_file_response(self) -> None:
        if self.flags.pac_file:
            try:
                with open(self.flags.pac_file, 'rb') as f:
                    content = f.read()
            except IOError:
                content = bytes_(self.flags.pac_file)
            self.pac_file_response = memoryview(build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                    b'Content-Encoding': b'gzip',
                }, body=gzip.compress(content)
            ))
