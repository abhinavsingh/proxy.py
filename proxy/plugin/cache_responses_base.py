import logging
import tempfile
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO, Any

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin

logger = logging.getLogger(__name__)


class BaseCacheResponsesPlugin(HttpProxyBasePlugin, ABC):
    """Base cache plugin."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(
            self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        try:
            self.cache_file_path = self.get_cache_file_path(request)
            self.cache_file = open(self.cache_file_path, "wb")
        except Exception as e:
            logger.info('Caching disabled due to %s', str(e))
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(
            self,
            chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
            logger.info('Cached response at %s', self.cache_file_path)

    @abstractmethod
    def get_cache_file_path(self, request: HttpParser) -> str:
        """Override for customizing cache paths or raise an exception to skip caching a particular request."""
        raise NotImplementedError()
