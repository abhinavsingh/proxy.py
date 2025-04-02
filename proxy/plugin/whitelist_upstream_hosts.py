# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    Whitelist Plugin modified from (broken) filter_by_upstream plugin by Mike Jones dr.mike.jones@gmail.com

"""
from typing import Optional

from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..common.utils import text_
from ..http.exception import HttpRequestRejected

flags.add_argument(
    '--whitelist-upstream-hosts',
    type=str,
    default='datasets.datalad.org,singularity-hub.org,galaxy-dev.mcfe.itservices.manchester.ac.uk',
    help='Default: Allows Singularity and Datasets.  Comma separated list of domains.',
)


class WhitelistUpstreamHostsPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if not request.host.decode() in self.flags.whitelist_upstream_hosts.split(','):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot cannot conect to '+request.host,
            )
        return request
