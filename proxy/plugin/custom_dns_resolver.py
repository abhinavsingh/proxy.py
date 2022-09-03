# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       dns
"""
import socket
from typing import Tuple, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.common.types import HostPort


class CustomDnsResolverPlugin(HttpProxyBasePlugin):
    """This plugin demonstrate how to use your own custom DNS resolver."""

    def resolve_dns(self, host: str, port: int) -> Tuple[Optional[str], Optional[HostPort]]:
        """Here we are using in-built python resolver for demonstration.

        Ideally you would like to query your custom DNS server or even
        use :term:`DoH` to make real sense out of this plugin.

        The second parameter returned is None.  Return a 2-tuple to
        configure underlying interface to use for connection to the
        upstream server.
        """
        try:
            return socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0], None
        except socket.gaierror:
            # Ideally we can also thrown HttpRequestRejected or HttpProtocolException here
            # Returning None simply fallback to core generated exceptions.
            return None, None
