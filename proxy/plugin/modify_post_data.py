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

from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser


class ModifyPostDataPlugin(HttpProxyBasePlugin):
    """Modify POST request body before sending to upstream server.

    Following curl executions will work:
        1. Plain
           curl -v -x localhost:8899 -X POST http://httpbin.org/post -d 'key=value'
        2. Chunked
           curl -v -x localhost:8899 -X POST \
               -H 'Transfer-Encoding: chunked' http://httpbin.org/post -d 'key=value'
        3. Chunked & Compressed
           echo 'key=value' | gzip | curl -v \
               -x localhost:8899 \
               -X POST \
               --data-binary @- -H 'Transfer-Encoding: chunked' \
               -H 'Content-Encoding: gzip' http://httpbin.org/post

    """

    MODIFIED_BODY = b'{"key": "modified"}'

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.body:
            request.update_body(
                ModifyPostDataPlugin.MODIFIED_BODY,
                content_type=b'application/json',
            )
        return request
