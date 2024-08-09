# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
from typing import Optional

from .parser import HttpParser, httpParserTypes
from ..common.utils import build_http_request, new_socket_connection
from ..common.constants import HTTPS_PROTO, DEFAULT_TIMEOUT


def client(
    host: bytes,
    port: int,
    path: bytes,
    method: bytes,
    body: Optional[bytes] = None,
    conn_close: bool = True,
    scheme: bytes = HTTPS_PROTO,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[HttpParser]:
    """Makes a request to remote registry endpoint"""
    request = build_http_request(
        method=method,
        url=path,
        headers={
            b'Host': host,
            b'Content-Type': b'application/x-www-form-urlencoded',
        },
        body=body,
        conn_close=conn_close,
    )
    try:
        conn = new_socket_connection((host.decode(), port))
    except ConnectionRefusedError:
        return None
    try:
        sock = (
            ssl.wrap_socket(sock=conn, ssl_version=ssl.PROTOCOL_TLSv1_2)
            if scheme == HTTPS_PROTO
            else conn
        )
    except Exception:
        conn.close()
        return None
    parser = HttpParser(
        httpParserTypes.RESPONSE_PARSER,
    )
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            parser.parse(memoryview(chunk))
            if parser.is_complete:
                break
    finally:
        sock.close()
    return parser
