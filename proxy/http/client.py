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
import logging
from typing import Optional

from .parser import HttpParser, httpParserTypes
from ..common.types import TcpOrTlsSocket
from ..common.utils import build_http_request, new_socket_connection
from ..common.constants import (
    HTTPS_PROTO, DEFAULT_TIMEOUT, DEFAULT_SSL_CONTEXT_OPTIONS,
)


logger = logging.getLogger(__name__)


def client(
    host: bytes,
    port: int,
    path: bytes,
    method: bytes,
    body: Optional[bytes] = None,
    conn_close: bool = True,
    scheme: bytes = HTTPS_PROTO,
    timeout: float = DEFAULT_TIMEOUT,
    content_type: bytes = b'application/x-www-form-urlencoded',
    verify: bool = True,
) -> Optional[HttpParser]:
    """HTTP Client"""
    request = build_http_request(
        method=method,
        url=path,
        headers={
            b'Host': host,
            b'Content-Type': content_type,
        },
        body=body,
        conn_close=conn_close,
    )
    try:
        conn = new_socket_connection((host.decode(), port))
    except Exception:
        # logger.exception('Cannot establish connection', exc_info=exc)
        return None
    sock: TcpOrTlsSocket = conn
    if scheme == HTTPS_PROTO:
        try:
            ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
            ctx.options |= DEFAULT_SSL_CONTEXT_OPTIONS
            ctx.check_hostname = verify
            ctx.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED
            ctx.load_default_certs()
            sock = ctx.wrap_socket(conn, server_hostname=host.decode())
        except Exception as exc:
            logger.exception('Unable to wrap', exc_info=exc)
            conn.close()
            return None
    parser = HttpParser(httpParserTypes.RESPONSE_PARSER)
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
