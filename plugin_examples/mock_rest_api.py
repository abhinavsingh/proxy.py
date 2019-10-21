# -*- coding: utf-8 -*-
"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
from typing import Optional

from proxy.http_parser import HttpParser
from proxy.http_proxy import HttpProxyBasePlugin
from proxy.status_codes import httpStatusCodes
from proxy.utils import bytes_, build_http_response, text_


class ProposedRestApiPlugin(HttpProxyBasePlugin):
    """Mock responses for your upstream REST API.

    Used to test and develop client side applications
    without need of an actual upstream REST API server.

    Returns proposed REST API mock responses to the client
    without establishing upstream connection.

    Note: This plugin won't work if your client is making
    HTTPS connection to api.example.com.
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
            ]
        },
    }

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        # Return None to disable establishing connection to upstream
        # Most likely our api.example.com won't even exist under development scenario
        return None

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        if request.host != self.API_SERVER:
            return request
        assert request.path
        if request.path in self.REST_API_SPEC:
            self.client.queue(build_http_response(
                httpStatusCodes.OK,
                reason=b'OK',
                headers={b'Content-Type': b'application/json'},
                body=bytes_(json.dumps(
                    self.REST_API_SPEC[request.path]))
            ))
        else:
            self.client.queue(build_http_response(
                httpStatusCodes.NOT_FOUND,
                reason=b'NOT FOUND', body=b'Not Found'
            ))
        return None

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
