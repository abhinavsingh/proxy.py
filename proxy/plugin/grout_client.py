# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


from typing import Tuple, Optional

from proxy.proxy import GroutClientBasePlugin
from proxy.common.types import HostPort
from proxy.http.parser.parser import HttpParser


class GroutClientPlugin(GroutClientBasePlugin):

    def resolve_route(
        self,
        route: str,
        request: HttpParser,
        origin: HostPort,
        server: HostPort,
    ) -> Tuple[Optional[str], HttpParser]:
        # print(request, origin, server, '->', route)
        # print(request.header(b'host'), request.path)
        #
        # Send to localhost:7001 irrespective of the
        # original "route" value provided to the grout client
        # OR any custom host:upstream mapping provided through the
        # --tunnel-route flags.
        #
        # Optionally, you can also strip path like this:
        # request.path = b"/"
        #
        # Return None for route to drop the request
        # return None, request
        #
        return 'http://localhost:7001', request
