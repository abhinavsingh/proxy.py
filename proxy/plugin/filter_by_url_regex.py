# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       url
"""
import json
import logging

from typing import Optional, List, Dict, Any

from ..common.flag import flags
from ..common.utils import text_

from ..http import httpStatusCodes
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin
from ..http.exception import HttpRequestRejected

import re

logger = logging.getLogger(__name__)

# See adblock.json file in repository for sample example config
flags.add_argument(
    '--filtered-url-regex-config',
    type=str,
    default='',
    help='Default: No config.  Comma separated list of IPv4 and IPv6 addresses.',
)


class FilterByURLRegexPlugin(HttpProxyBasePlugin):
    """Drops traffic by inspecting request URL and checking
    against a list of regular expressions.  Example, default
    filter list below can be used as a starting point for
    filtering ads.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.filters: List[Dict[str, Any]] = []
        if self.flags.filtered_url_regex_config != '':
            with open(self.flags.filtered_url_regex_config, 'rb') as f:
                self.filters = json.load(f)

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        # determine host
        request_host = None
        if request.host:
            request_host = request.host
        elif request.headers and b'host' in request.headers:
            request_host = request.header(b'host')

        if not request_host:
            logger.error("Cannot determine host")
            return request

        # build URL
        url = b'%s%s' % (
            request_host,
            request.path,
        )
        # check URL against list
        rule_number = 1
        for blocked_entry in self.filters:
            # if regex matches on URL
            if re.search(text_(blocked_entry['regex']), text_(url)):
                # log that the request has been filtered
                logger.info(
                    "Blocked: %r with status_code '%r' by rule number '%r'" % (
                        text_(url),
                        httpStatusCodes.NOT_FOUND,
                        rule_number,
                    ),
                )
                # close the connection with the status code from the filter
                # list
                raise HttpRequestRejected(
                    status_code=httpStatusCodes.NOT_FOUND,
                    reason=b'Blocked',
                )
                # stop looping through filter list
                break
            # increment rule number
            rule_number += 1
        return request
