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
from typing import List, Tuple, Union

from ..http import Url
from ..http.parser import HttpParser
from ..http.server import ReverseProxyBasePlugin
from ..http.exception.base import HttpProtocolException


class ReverseProxyPlugin(ReverseProxyBasePlugin):
    """This example plugin is equivalent to following Nginx configuration::

        ```text
        location /get {
            proxy_pass http://httpbin.org/get
        }
        ```

    Plugin also demonstrates how to write "Python" equivalent for any
    "Nginx Lua" based configuration i.e. your plugin code will have
    full control over what do after one of your route has matched.
    """

    def routes(self) -> List[Union[str, Tuple[str, List[bytes]]]]:
        return [
            # A static route
            (
                r'/get$',
                [b'http://httpbin.org/get', b'https://httpbin.org/get']
            ),
            # A dynamic route to catch requests on `/get/<int>`
            # See `handle_route` method for what we do when a pattern matches.
            r'/get/(\d+)$',
        ]

    def handle_route(self, request: HttpParser, pattern: re.Pattern) -> Url:
        """For our example dynamic route, we want to simply convert
        any incoming request to `/get/1` into `/get?id=1` when serving from upstream.
        """
        choice: Url = Url.from_bytes(b'http://httpbin.org/get')
        assert request.path
        result = re.search(pattern, request.path.decode())
        if not result or len(result.groups()) != 1:
            raise HttpProtocolException("Invalid request")
        assert choice.remainder == b'/get'
        # NOTE: Internally, reverse proxy core replaces
        # original request.path with the choice.remainder value.
        # e.g. for this example, request.path will be `/get/1`.
        # Core will automatically replace that with `/get?id=1`
        # before dispatching request to choice of upstream server.
        choice.remainder += f'?id={result.groups()[0]}'.encode()
        return choice
