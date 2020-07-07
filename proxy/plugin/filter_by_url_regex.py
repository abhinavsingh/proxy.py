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

from ..http.exception import HttpRequestRejected
from ..http.parser import HttpParser
from ..http.codes import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin

import re

class FilterByURLRegexPlugin(HttpProxyBasePlugin):
    """
        Drop traffic by inspecting request URL, 
        checking against a list of regular expressions, 
        then returning a HTTP status code.
    """

    FILTER_LIST = [
        {
            b'regex': b'https{0,1}://tpc.googlesyndication.com:\d{1,5}/simgad/.*',
            b'status_code': 444
        },
    ]

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        
        # build URL
        url = b'http://%s:%d%s' % (
            request.host, 
            request.port,
            request.path,
        )

        # check URL against list
        for blocked_entry in self.FILTER_LIST:
            if re.search(blocked_entry['regex'], url):
                raise HttpRequestRejected(
                    status_code = blocked_entry['status_code'],
                    headers = {b'Connection': b'close'}
                )
                break

        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
