# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import Optional, Any

from .store.base import CacheStore
from ...http.parser import HttpParser, httpParserTypes
from ...http.proxy import HttpProxyBasePlugin
from ...http.codes import httpStatusCodes
from ...common.constants import PROXY_AGENT_HEADER_VALUE
from ...common.utils import text_
from ...common.utils import build_http_response

logger = logging.getLogger(__name__)


class BaseCacheResponsesPlugin(HttpProxyBasePlugin):
    """Base cache plugin.

    Cache plugin requires a storage backend to work with.
    Storage class must implement this interface.
    """

    def __init__(
            self,
            *args: Any,
            **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.store: Optional[CacheStore] = None

    def set_store(self, store: CacheStore) -> None:
        self.store = store

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        assert self.store
        logger.info("Upstream connexion %s:%d %s" %
                    (text_(request.host), request.port if request.port else 0, text_(request.path)))

        if request.port == 443:
            return request

        try:
            if self.store.is_cached(request):
                return None
        except Exception as e:
            logger.info(
                'Caching disabled due to exception message: %s',
                str(e))

        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        assert self.store
        logger.info("Client request %s:%d %s" %
                    (text_(request.host), request.port if request.port else 0, text_(request.path)))

        if request.port == 443:
            return request

        try:
            msg = self.store.cache_request(request)
            if (msg.type == httpParserTypes.REQUEST_PARSER):
                return msg
            elif (msg.type == httpParserTypes.RESPONSE_PARSER):
                self.client.queue(memoryview(build_http_response(
                    int(msg.code) if msg.code is not None else 0,
                    reason=msg.reason,
                    headers={k: v for k, v in msg.headers.values()},
                    body=msg.body
                )))
                return None
            else:
                raise ValueError('Bad HTTPParser type: %s' % msg.type)
        except Exception as e:
            logger.info(
                'Caching disabled due to exception message: %s',
                str(e))

        try:
            if self.store.is_cached(request):
                self.client.queue(memoryview(build_http_response(
                    httpStatusCodes.INTERNAL_SERVER_ERROR,
                    reason=b'Internal server error',
                    headers={
                        b'Server': PROXY_AGENT_HEADER_VALUE,
                        b'Connection': b'close',
                    }
                )))
        except Exception as e:
            logger.info(
                'Caching disabled due to exception message: %s',
                str(e))

        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        assert self.store
        return self.store.cache_response_chunk(chunk)

    def on_upstream_connection_close(self) -> None:
        assert self.store
        self.store.close()
