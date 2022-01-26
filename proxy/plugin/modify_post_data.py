# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from ..http import httpMethods
from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser, ChunkParser
from ..common.utils import bytes_


class ModifyPostDataPlugin(HttpProxyBasePlugin):
    """Modify POST request body before sending to upstream server."""

    MODIFIED_BODY = b'{"key": "modified"}'

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.method == httpMethods.POST:
            # If request data is compressed, compress the body too
            body = ModifyPostDataPlugin.MODIFIED_BODY
            # If the request is of type chunked encoding
            # add post data as chunk
            if not request.is_chunked_encoded:
                body = ChunkParser.to_chunks(
                    ModifyPostDataPlugin.MODIFIED_BODY,
                )
            else:
                request.add_header(
                    b'Content-Length',
                    bytes_(len(body)),
                )
            request.body = body
            # Enforce content-type json
            if request.has_header(b'Content-Type'):
                request.del_header(b'Content-Type')
            request.add_header(b'Content-Type', b'application/json')
        return request
