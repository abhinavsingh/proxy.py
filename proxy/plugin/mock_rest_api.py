# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       api
"""
import json
from typing import Optional

from ..common.utils import bytes_, text_

from ..http.responses import okResponse, NOT_FOUND_RESPONSE_PKT
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin


class ProposedRestApiPlugin(HttpProxyBasePlugin):
    """Mock responses for your upstream REST API.

    Used to test and develop client side applications
    without need of an actual upstream REST API server.

    Returns proposed REST API mock responses to the client
    without establishing upstream connection.

    Note: This plugin won't work if your client is making
    HTTPS connection to ``api.example.com``.
    """

    API_SERVER = b'api.example.com'

    REST_API_SPEC = {
        b'/v1/users/': {
            'count': 2,
            'next': None,
            'previous': None,
            'results': [
                {
                    'email': 'you@example.com',
                    'groups': [],
                    'url': text_(API_SERVER) + '/v1/users/1/',
                    'username': 'admin',
                },
                {
                    'email': 'someone@example.com',
                    'groups': [],
                    'url': text_(API_SERVER) + '/v1/users/2/',
                    'username': 'someone',
                },
            ],
        },
    }

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        # Return None to disable establishing connection to upstream
        # Most likely our api.example.com won't even exist under development
        # scenario
        return None

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.host != self.API_SERVER:
            return request
        assert request.path
        if request.path in self.REST_API_SPEC:
            self.client.queue(
                okResponse(
                    headers={b'Content-Type': b'application/json'},
                    content=bytes_(
                        json.dumps(
                            self.REST_API_SPEC[request.path],
                        ),
                    )
                )
            )
        else:
            self.client.queue(NOT_FOUND_RESPONSE_PKT)
        return None
