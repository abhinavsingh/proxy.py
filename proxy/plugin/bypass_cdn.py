import time
from typing import Optional
from urllib import parse as urlparse

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin


class BypassCDNPlugin(HttpProxyBasePlugin):
    """this will force upstream servers to almost always invalidate the cache via add query params
    
    Reference: 
      - https://i.blackhat.com/USA-20/Wednesday/us-20-Kettle-Web-Cache-Entanglement-Novel-Pathways-To-Poisoning-wp.pdf
      - https://cloud.google.com/cdn/docs/caching#cache-keys
    """

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        new_url = f'{request.url.geturl().decode()}?timestamp={int(round(time.time() * 1000))}'
        request.set_url(new_url.encode())

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass