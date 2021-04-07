# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import re
from typing import Optional

from ..common.flag import flags
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin

DEFAULT_HEADER = "X-Proxy-Py:Proxied with proxy.py"

flags.add_argument(
    '--add-header',
    action='append',
    default=[],
    help=f'Default: "{DEFAULT_HEADER}". Headers to add before dispatching '
    'client request to upstream server. Can be specified multiple times. '
    'Headers should be in the format header:value. '
    'Any colon in the header value must be escapped with a slash '
    '(e.g. X-Header:my\\:value)',
)

COLON_RE = re.compile(r"(?<!\\):")


class AddHeaderPlugin(HttpProxyBasePlugin):
    """Add header before sending to upstream server."""

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        if not self.flags.add_header:
            self.flags.add_header = [DEFAULT_HEADER]

        for header in self.flags.add_header:
            header_name, header_value = COLON_RE.split(header)
            header_value = header_value.replace('\\:', ':')
            request.add_header(header_name.encode(), header_value.encode())

        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
