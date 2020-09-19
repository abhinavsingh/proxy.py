import time
from typing import Optional
from urllib import parse as urlparse

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin


class ShiroBypassCDNPlugin(HttpProxyBasePlugin):
    """因为cdn缓存的存在导致shiro执行失败，通过变换url query参数进行绕过"""

    FLAG = b'/r/cms/jquery.js'

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        if ShiroBypassCDNPlugin.FLAG in request.url.path:
            new_url = f'{request.url.geturl().decode()}?{int(round(time.time() * 1000))}'
            request.set_url(new_url.encode())
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass