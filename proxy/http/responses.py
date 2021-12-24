# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import gzip
from typing import Dict, Optional

from ..common.flag import flags
from ..common.utils import build_http_response
from ..common.constants import PROXY_AGENT_HEADER_VALUE, PROXY_AGENT_HEADER_KEY

from .codes import httpStatusCodes


PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = memoryview(
    build_http_response(
        httpStatusCodes.OK,
        reason=b'Connection established',
    ),
)

PROXY_TUNNEL_UNSUPPORTED_SCHEME = memoryview(
    build_http_response(
        httpStatusCodes.BAD_REQUEST,
        reason=b'Unsupported protocol scheme',
        conn_close=True,
    ),
)

PROXY_AUTH_FAILED_RESPONSE_PKT = memoryview(
    build_http_response(
        httpStatusCodes.PROXY_AUTH_REQUIRED,
        reason=b'Proxy Authentication Required',
        headers={
            PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
            b'Proxy-Authenticate': b'Basic',
        },
        body=b'Proxy Authentication Required',
        conn_close=True,
    ),
)

NOT_FOUND_RESPONSE_PKT = memoryview(
    build_http_response(
        httpStatusCodes.NOT_FOUND,
        reason=b'NOT FOUND',
        headers={
            b'Server': PROXY_AGENT_HEADER_VALUE,
            b'Content-Length': b'0',
        },
        conn_close=True,
    ),
)

NOT_IMPLEMENTED_RESPONSE_PKT = memoryview(
    build_http_response(
        httpStatusCodes.NOT_IMPLEMENTED,
        reason=b'NOT IMPLEMENTED',
        headers={
            b'Server': PROXY_AGENT_HEADER_VALUE,
            b'Content-Length': b'0',
        },
        conn_close=True,
    ),
)

BAD_GATEWAY_RESPONSE_PKT = memoryview(
    build_http_response(
        httpStatusCodes.BAD_GATEWAY,
        reason=b'Bad Gateway',
        headers={
            PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
        },
        body=b'Bad Gateway',
        conn_close=True,
    ),
)


def okResponse(
        content: Optional[bytes] = None,
        headers: Optional[Dict[bytes, bytes]] = None,
        conn_close: bool = False,
) -> memoryview:
    do_compress = flags.args and \
        content and \
        len(content) > flags.args.min_compression_limit
    if do_compress:
        if not headers:
            headers = {}
        headers.update({
            b'Content-Encoding': b'gzip',
        })
    return memoryview(
        build_http_response(
            200,
            reason=b'OK',
            headers=headers,
            body=gzip.compress(content)
            if do_compress and content
            else content,
            conn_close=conn_close,
        ),
    )


def permanentRedirectResponse(location: bytes) -> memoryview:
    return memoryview(
        build_http_response(
            httpStatusCodes.PERMANENT_REDIRECT,
            reason=b'Permanent Redirect',
            headers={
                b'Location': location,
                b'Content-Length': b'0',
            },
            conn_close=True,
        ),
    )


def seeOthersResponse(location: bytes) -> memoryview:
    return memoryview(
        build_http_response(
            httpStatusCodes.SEE_OTHER,
            reason=b'See Other',
            headers={
                b'Location': location,
                b'Content-Length': b'0',
            },
            conn_close=True,
        ),
    )
