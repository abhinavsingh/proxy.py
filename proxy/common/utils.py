# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       utils
       websocket
       Websocket
       WebSocket
"""
import sys
import ssl
import time
import socket
import logging
import functools
import ipaddress
import contextlib

from types import TracebackType
from typing import Optional, Dict, Any, List, Tuple, Type, Callable

from ._compat import IS_WINDOWS  # noqa: WPS436
from .constants import HTTP_1_1, COLON, WHITESPACE, CRLF, DEFAULT_TIMEOUT, DEFAULT_THREADLESS

if not IS_WINDOWS:
    import resource

logger = logging.getLogger(__name__)


def is_threadless(threadless: bool, threaded: bool) -> bool:
    # if default is threadless then return true unless
    # user has overridden mode using threaded flag.
    #
    # if default is not threadless then return true
    # only if user has overridden using --threadless flag
    return (DEFAULT_THREADLESS and not threaded) or (not DEFAULT_THREADLESS and threadless)


def is_py2() -> bool:
    """Exists only to avoid mocking :data:`sys.version_info` in tests."""
    return sys.version_info.major == 2


def text_(s: Any, encoding: str = 'utf-8', errors: str = 'strict') -> Any:
    """Utility to ensure text-like usability.

    If s is of type bytes or int, return s.decode(encoding, errors),
    otherwise return s as it is."""
    if isinstance(s, int):
        return str(s)
    if isinstance(s, bytes):
        return s.decode(encoding, errors)
    return s


def bytes_(s: Any, encoding: str = 'utf-8', errors: str = 'strict') -> Any:
    """Utility to ensure binary-like usability.

    If s is type str or int, return s.encode(encoding, errors),
    otherwise return s as it is."""
    if isinstance(s, int):
        s = str(s)
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s


def build_http_request(
    method: bytes, url: bytes,
    protocol_version: bytes = HTTP_1_1,
    headers: Optional[Dict[bytes, bytes]] = None,
    body: Optional[bytes] = None,
) -> bytes:
    """Build and returns a HTTP request packet."""
    if headers is None:
        headers = {}
    return build_http_pkt(
        [method, url, protocol_version], headers, body,
    )


def build_http_response(
    status_code: int,
    protocol_version: bytes = HTTP_1_1,
    reason: Optional[bytes] = None,
    headers: Optional[Dict[bytes, bytes]] = None,
    body: Optional[bytes] = None,
) -> bytes:
    """Build and returns a HTTP response packet."""
    line = [protocol_version, bytes_(status_code)]
    if reason:
        line.append(reason)
    if headers is None:
        headers = {}
    has_content_length = False
    has_transfer_encoding = False
    for k in headers:
        if k.lower() == b'content-length':
            has_content_length = True
        if k.lower() == b'transfer-encoding':
            has_transfer_encoding = True
    if body is not None and \
            not has_transfer_encoding and \
            not has_content_length:
        headers[b'Content-Length'] = bytes_(len(body))
    return build_http_pkt(line, headers, body)


def build_http_header(k: bytes, v: bytes) -> bytes:
    """Build and return a HTTP header line for use in raw packet."""
    return k + COLON + WHITESPACE + v


def build_http_pkt(
    line: List[bytes],
    headers: Optional[Dict[bytes, bytes]] = None,
    body: Optional[bytes] = None,
) -> bytes:
    """Build and returns a HTTP request or response packet."""
    pkt = WHITESPACE.join(line) + CRLF
    if headers is not None:
        for k in headers:
            pkt += build_http_header(k, headers[k]) + CRLF
    pkt += CRLF
    if body:
        pkt += body
    return pkt


def build_websocket_handshake_request(
        key: bytes,
        method: bytes = b'GET',
        url: bytes = b'/',
        host: bytes = b'localhost',
) -> bytes:
    """
    Build and returns a Websocket handshake request packet.

    :param key: Sec-WebSocket-Key header value.
    :param method: HTTP method.
    :param url: Websocket request path.
    """
    return build_http_request(
        method, url,
        headers={
            b'Host': host,
            b'Connection': b'upgrade',
            b'Upgrade': b'websocket',
            b'Sec-WebSocket-Key': key,
            b'Sec-WebSocket-Version': b'13',
        },
    )


def build_websocket_handshake_response(accept: bytes) -> bytes:
    """
    Build and returns a Websocket handshake response packet.

    :param accept: Sec-WebSocket-Accept header value
    """
    return build_http_response(
        101, reason=b'Switching Protocols',
        headers={
            b'Upgrade': b'websocket',
            b'Connection': b'Upgrade',
            b'Sec-WebSocket-Accept': accept,
        },
    )


def find_http_line(raw: bytes) -> Tuple[Optional[bytes], bytes]:
    """Find and returns first line ending in CRLF along with following buffer.

    If no ending CRLF is found, line is None."""
    parts = raw.split(CRLF)
    if len(parts) == 1:
        return None, raw
    return parts[0], CRLF.join(parts[1:])


def wrap_socket(
    conn: socket.socket, keyfile: str,
    certfile: str,
) -> ssl.SSLSocket:
    """Use this to upgrade server_side socket to TLS."""
    ctx = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH,
    )
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(
        certfile=certfile,
        keyfile=keyfile,
    )
    return ctx.wrap_socket(
        conn,
        server_side=True,
    )


def new_socket_connection(
        addr: Tuple[str, int],
        timeout: float = DEFAULT_TIMEOUT,
        source_address: Optional[Tuple[str, int]] = None,
) -> socket.socket:
    conn = None
    try:
        ip = ipaddress.ip_address(addr[0])
        if ip.version == 4:
            conn = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM, 0,
            )
            conn.settimeout(timeout)
            conn.connect(addr)
        else:
            conn = socket.socket(
                socket.AF_INET6, socket.SOCK_STREAM, 0,
            )
            conn.settimeout(timeout)
            conn.connect((addr[0], addr[1], 0, 0))
    except ValueError:
        pass    # does not appear to be an IPv4 or IPv6 address

    if conn is not None:
        return conn

    # try to establish dual stack IPv4/IPv6 connection.
    return socket.create_connection(addr, timeout=timeout, source_address=source_address)


class socket_connection(contextlib.ContextDecorator):
    """Same as new_socket_connection but as a context manager and decorator."""

    def __init__(self, addr: Tuple[str, int]):
        self.addr: Tuple[str, int] = addr
        self.conn: Optional[socket.socket] = None
        super().__init__()

    def __enter__(self) -> socket.socket:
        self.conn = new_socket_connection(self.addr)
        return self.conn

    def __exit__(
            self,
            exc_type: Optional[Type[BaseException]],
            exc_val: Optional[BaseException],
            exc_tb: Optional[TracebackType],
    ) -> None:
        if self.conn:
            self.conn.close()

    def __call__(   # type: ignore
            self, func: Callable[..., Any],
    ) -> Callable[[Tuple[Any, ...], Dict[str, Any]], Any]:
        @functools.wraps(func)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            with self as conn:
                return func(conn, *args, **kwargs)
        return decorated


def get_available_port() -> int:
    """Finds and returns an available port on the system."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
    return int(port)


def set_open_file_limit(soft_limit: int) -> None:
    """Configure open file description soft limit on supported OS."""
    if IS_WINDOWS:  # resource module not available on Windows OS
        return

    curr_soft_limit, curr_hard_limit = resource.getrlimit(
        resource.RLIMIT_NOFILE,
    )
    if curr_soft_limit < soft_limit < curr_hard_limit:
        resource.setrlimit(
            resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit),
        )
        logger.debug(
            'Open file soft limit set to %d', soft_limit,
        )


class cached_property(object):
    """Decorator for read-only properties evaluated only once within TTL period.
    It can be used to create a cached property like this::

        import random

        # the class containing the property must be a new-style class
        class MyClass(object):
            # create property whose value is cached for ten minutes
            @cached_property(ttl=600)
            def randint(self):
                # will only be evaluated every 10 min. at maximum.
                return random.randint(0, 100)

    The value is cached  in the '_cached_properties' attribute of the object instance that
    has the property getter method wrapped by this decorator. The '_cached_properties'
    attribute value is a dictionary which has a key for every property of the
    object which is wrapped by this decorator. Each entry in the cache is
    created only when the property is accessed for the first time and is a
    two-element tuple with the last computed property value and the last time
    it was updated in seconds since the epoch.

    The default time-to-live (TTL) is 300 seconds (5 minutes). Set the TTL to
    zero for the cached value to never expire.

    To expire a cached property value manually just do::
        del instance._cached_properties[<property name>]

    Adopted from https://wiki.python.org/moin/PythonDecoratorLibrary#Cached_Properties
    © 2011 Christopher Arndt, MIT License.

    NOTE: We need this function only because Python in-built are only available
    for 3.8+.  Hence, we must get rid of this function once proxy.py no longer
    support version older than 3.8.

    .. spelling::

       getter
       Arndt
    """

    def __init__(self, ttl: float = 300.0):
        self.ttl = ttl

    def __call__(self, fget: Any, doc: Any = None) -> 'cached_property':
        self.fget = fget
        self.__doc__ = doc or fget.__doc__
        self.__name__ = fget.__name__
        self.__module__ = fget.__module__
        return self

    def __get__(self, inst: Any, owner: Any) -> Any:
        now = time.time()
        try:
            value, last_update = inst._cached_properties[self.__name__]
            if self.ttl > 0 and now - last_update > self.ttl:   # noqa: WPS333
                raise AttributeError
        except (KeyError, AttributeError):
            value = self.fget(inst)
            try:
                cache = inst._cached_properties
            except AttributeError:
                cache, inst._cached_properties = {}, {}
            finally:
                cache[self.__name__] = (value, now)
        return value
