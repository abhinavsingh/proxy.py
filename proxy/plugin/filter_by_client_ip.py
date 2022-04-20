# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       ip
"""
from typing import Optional

from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..http.exception import HttpRequestRejected


flags.add_argument(
    '--filtered-client-ips-mode',
    type=str,
    default='blacklist',
    help='Default: blacklist.  Can be either "whitelist" (restrict access to specific IPs) or "blacklist" (allow everything except specific IPs).',
)

flags.add_argument(
    '--filtered-client-ips',
    type=str,
    default='127.0.0.1,::1',
    help='Default: 127.0.0.1,::1.  Comma separated list of IPv4 and IPv6 addresses.',
)


class FilterByClientIpPlugin(HttpProxyBasePlugin):
    """Allow only (whitelist) or Drop only (blacklist) traffic by inspecting incoming client IP address."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        assert not self.flags.unix_socket_path and self.client.addr and self.flags.filtered_client_ips_mode in ('blacklist','whitelist')
        if self.flags.filtered_client_ips_mode == 'blacklist':
            if self.client.addr[0] in self.flags.filtered_client_ips.split(','):
                raise HttpRequestRejected(
                    status_code=httpStatusCodes.I_AM_A_TEAPOT,
                    reason=b'I\'m a tea pot',
                )
        elif self.flags.filtered_client_ips_mode == 'whitelist':
            if self.client.addr[0] not in self.flags.filtered_client_ips.split(','):
                raise HttpRequestRejected(
                    status_code=httpStatusCodes.I_AM_A_TEAPOT,
                    reason=b'I\'m a tea pot',
                )
        return request
