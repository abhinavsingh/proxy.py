# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import List, Tuple

from ..http.server import ReverseProxyBasePlugin


# TODO: We must use nginx python parser and
# make this plugin nginx.conf complaint.
REVERSE_PROXY_LOCATION: str = r'/get$'
# Randomly choose either http or https upstream endpoint.
#
# This is just to demonstrate that both http and https upstream
# reverse proxy works.
REVERSE_PROXY_PASS = [
    b'http://httpbin.org/get',
    b'https://httpbin.org/get',
]


class ReverseProxyPlugin(ReverseProxyBasePlugin):
    """This example plugin is equivalent to following Nginx configuration::

        ```text
        location /get {
            proxy_pass http://httpbin.org/get
        }
        ```

    Example::

        ```console
        $ curl http://localhost:9000/get
        {
          "args": {},
          "headers": {
            "Accept": "*/*",
            "Host": "localhost",
            "User-Agent": "curl/7.64.1"
          },
          "origin": "1.2.3.4, 5.6.7.8",
          "url": "http://localhost/get"
        }
        ```
    """

    def routes(self) -> List[Tuple[str, List[bytes]]]:
        return [(REVERSE_PROXY_LOCATION, REVERSE_PROXY_PASS)]
