# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""

class CacheResponsesPlugin(proxy.HttpProxyBasePlugin):
    """Caches Upstream Server Responses."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(
            self,
            config: proxy.Flags,
            client: proxy.TcpClientConnection) -> None:
        super().__init__(config, client)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        # Ideally should only create file if upstream connection succeeds.
        self.cache_file_path = os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (proxy.text_(request.host), str(time.time())))
        self.cache_file = open(self.cache_file_path, "wb")
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self,
                              chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
        proxy.logger.info('Cached response at %s', self.cache_file_path)
