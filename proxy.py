#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    Lightweight, Programmable, TLS interceptor Proxy for HTTP(S), HTTP2, WebSockets protocols in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import base64
import datetime
import errno
import hashlib
import importlib
import inspect
import io
import ipaddress
import json
import logging
import mimetypes
import multiprocessing
import os
import pathlib
import queue
import secrets
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle
from typing import Any, Dict, List, Tuple, Optional, Union, NamedTuple, Callable, TYPE_CHECKING
from urllib import parse as urlparse

from typing_extensions import Protocol

if os.name != 'nt':
    import resource

VERSION = (1, 0, 1)
__version__ = '.'.join(map(str, VERSION[0:3]))
__description__ = 'Lightweight, Programmable, TLS interceptor Proxy for HTTP(S), HTTP2, ' \
                  'WebSockets protocols in a single Python file.'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

logger = logging.getLogger(__name__)
PROXY_PY_DIR = os.path.dirname(os.path.realpath(__file__))
START_TIME = time.time()

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_CA_KEY_FILE = None
DEFAULT_CA_CERT_DIR = None
DEFAULT_CA_CERT_FILE = None
DEFAULT_CA_SIGNING_KEY_FILE = None
DEFAULT_CERT_FILE = None
DEFAULT_BUFFER_SIZE = 1024 * 1024
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_DISABLE_HEADERS: List[bytes] = []
DEFAULT_IPV4_HOSTNAME = ipaddress.IPv4Address('127.0.0.1')
DEFAULT_IPV6_HOSTNAME = ipaddress.IPv6Address('::1')
DEFAULT_KEY_FILE = None
DEFAULT_PORT = 8899
DEFAULT_DISABLE_HTTP_PROXY = False
DEFAULT_ENABLE_DEVTOOLS = False
DEFAULT_ENABLE_STATIC_SERVER = False
DEFAULT_ENABLE_WEB_SERVER = False
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_PAC_FILE_URL_PATH = b'/'
DEFAULT_PID_FILE = None
DEFAULT_NUM_WORKERS = 0
DEFAULT_PLUGINS = ''    # Comma separated list of plugins
DEFAULT_STATIC_SERVER_DIR = os.path.join(PROXY_PY_DIR, 'public')
DEFAULT_VERSION = False
DEFAULT_LOG_FORMAT = '%(asctime)s - %(levelname)s - pid:%(process)d - %(funcName)s:%(lineno)d - %(message)s'
DEFAULT_LOG_FILE = None

# Set to True if under test
UNDER_TEST = False


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


version = bytes_(__version__)
CRLF, COLON, WHITESPACE, COMMA, DOT = b'\r\n', b':', b' ', b',', b'.'
PROXY_AGENT_HEADER_KEY = b'Proxy-agent'
PROXY_AGENT_HEADER_VALUE = b'proxy.py v' + version
PROXY_AGENT_HEADER = PROXY_AGENT_HEADER_KEY + \
    COLON + WHITESPACE + PROXY_AGENT_HEADER_VALUE

###############################################################
# Various NamedTuples
#
# collections.namedtuple were replaced with typing.NamedTuple
# for mypy compliance. Unfortunately, we can't seem to use
# a NamedTuple as a type.
###############################################################

TcpConnectionTypes = NamedTuple('TcpConnectionTypes', [
    ('SERVER', int),
    ('CLIENT', int),
])
tcpConnectionTypes = TcpConnectionTypes(1, 2)

ChunkParserStates = NamedTuple('ChunkParserStates', [
    ('WAITING_FOR_SIZE', int),
    ('WAITING_FOR_DATA', int),
    ('COMPLETE', int),
])
chunkParserStates = ChunkParserStates(1, 2, 3)

HttpParserStates = NamedTuple('HttpParserStates', [
    ('INITIALIZED', int),
    ('LINE_RCVD', int),
    ('RCVING_HEADERS', int),
    ('HEADERS_COMPLETE', int),
    ('RCVING_BODY', int),
    ('COMPLETE', int),
])
httpParserStates = HttpParserStates(1, 2, 3, 4, 5, 6)

HttpParserTypes = NamedTuple('HttpParserTypes', [
    ('REQUEST_PARSER', int),
    ('RESPONSE_PARSER', int),
])
httpParserTypes = HttpParserTypes(1, 2)

HttpProtocolTypes = NamedTuple('HttpProtocolTypes', [
    ('HTTP', int),
    ('HTTPS', int),
    ('WEBSOCKET', int),
])
httpProtocolTypes = HttpProtocolTypes(1, 2, 3)

WebsocketOpcodes = NamedTuple('WebsocketOpcodes', [
    ('CONTINUATION_FRAME', int),
    ('TEXT_FRAME', int),
    ('BINARY_FRAME', int),
    ('CONNECTION_CLOSE', int),
    ('PING', int),
    ('PONG', int),
])
websocketOpcodes = WebsocketOpcodes(0x0, 0x1, 0x2, 0x8, 0x9, 0xA)


def build_http_request(method: bytes, url: bytes,
                       protocol_version: bytes = b'HTTP/1.1',
                       headers: Optional[Dict[bytes, bytes]] = None,
                       body: Optional[bytes] = None) -> bytes:
    """Build and returns a HTTP request packet."""
    if headers is None:
        headers = {}
    return build_http_pkt(
        [method, url, protocol_version], headers, body)


def build_http_response(status_code: int,
                        protocol_version: bytes = b'HTTP/1.1',
                        reason: Optional[bytes] = None,
                        headers: Optional[Dict[bytes, bytes]] = None,
                        body: Optional[bytes] = None) -> bytes:
    """Build and returns a HTTP response packet."""
    line = [protocol_version, bytes_(status_code)]
    if reason:
        line.append(reason)
    if headers is None:
        headers = {}
    if body is not None and not any(
            k.lower() == b'content-length' for k in headers):
        headers[b'Content-Length'] = bytes_(len(body))
    return build_http_pkt(line, headers, body)


def build_http_header(k: bytes, v: bytes) -> bytes:
    """Build and return a HTTP header line for use in raw packet."""
    return k + COLON + WHITESPACE + v


def build_http_pkt(line: List[bytes],
                   headers: Optional[Dict[bytes, bytes]] = None,
                   body: Optional[bytes] = None) -> bytes:
    """Build and returns a HTTP request or response packet."""
    req = WHITESPACE.join(line) + CRLF
    if headers is not None:
        for k in headers:
            req += build_http_header(k, headers[k]) + CRLF
    req += CRLF
    if body:
        req += body
    return req


def build_websocket_handshake_request(
        key: bytes,
        method: bytes = b'GET',
        url: bytes = b'/') -> bytes:
    """
    Build and returns a Websocket handshake request packet.

    :param key: Sec-WebSocket-Key header value.
    :param method: HTTP method.
    :param url: Websocket request path.
    """
    return build_http_request(
        method, url,
        headers={
            b'Connection': b'upgrade',
            b'Upgrade': b'websocket',
            b'Sec-WebSocket-Key': key,
            b'Sec-WebSocket-Version': b'13',
        }
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
            b'Sec-WebSocket-Accept': accept
        }
    )


def find_http_line(raw: bytes) -> Tuple[Optional[bytes], bytes]:
    """Find and returns first line ending in CRLF along with following buffer.

    If no ending CRLF is found, line is None."""
    pos = raw.find(CRLF)
    if pos == -1:
        return None, raw
    line = raw[:pos]
    rest = raw[pos + len(CRLF):]
    return line, rest


def new_socket_connection(addr: Tuple[str, int]) -> socket.socket:
    """Attempts to create an IPv4 connection, then IPv6 and finally dual stack connection.

    Returns established socket connection if successful,
    otherwise an exception is raised."""
    try:
        ip = ipaddress.ip_address(addr[0])
        if ip.version == 4:
            conn = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM, 0)
            conn.connect(addr)
        else:
            conn = socket.socket(
                socket.AF_INET6, socket.SOCK_STREAM, 0)
            conn.connect((addr[0], addr[1], 0, 0))
    except ValueError:
        # Not a valid IP address, most likely its a domain name,
        # try to establish dual stack IPv4/IPv6 connection.
        conn = socket.create_connection(addr)
    return conn


class _HasFileno(Protocol):
    def fileno(self) -> int:
        ...     # pragma: no cover


class TcpConnectionUninitializedException(Exception):
    pass


class TcpConnection(ABC):
    """TCP server/client connection abstraction.

    Main motivation of this class is to provide a buffer management
    when reading and writing into the socket.

    Implement the connection property abstract method to return
    a socket connection object."""

    def __init__(self, tag: int):
        self.buffer: bytes = b''
        self.closed: bool = False
        self.tag: str = 'server' if tag == tcpConnectionTypes.SERVER else 'client'

    @property
    @abstractmethod
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        """Must return the socket connection to use in this class."""
        raise TcpConnectionUninitializedException()     # pragma: no cover

    def send(self, data: bytes) -> int:
        """Users must handle BrokenPipeError exceptions"""
        return self.connection.send(data)

    def recv(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> Optional[bytes]:
        try:
            data: bytes = self.connection.recv(buffer_size)
            if len(data) > 0:
                logger.debug(
                    'received %d bytes from %s' %
                    (len(data), self.tag))
                return data
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                logger.debug('%r' % e)
            else:
                logger.exception(
                    'Exception while receiving from connection %s %r with reason %r' %
                    (self.tag, self.connection, e))
        return None

    def close(self) -> bool:
        if not self.closed:
            self.connection.close()
            self.closed = True
        return self.closed

    def buffer_size(self) -> int:
        return len(self.buffer)

    def has_buffer(self) -> bool:
        return self.buffer_size() > 0

    def queue(self, data: bytes) -> int:
        self.buffer += data
        return len(data)

    def flush(self) -> int:
        if self.buffer_size() == 0:
            return 0
        sent: int = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        logger.debug('flushed %d bytes to %s' % (sent, self.tag))
        return sent


class TcpServerConnection(TcpConnection):
    """Establishes connection to upstream server."""

    def __init__(self, host: str, port: int):
        super().__init__(tcpConnectionTypes.SERVER)
        self.addr: Tuple[str, int] = (host, int(port))
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn

    def connect(self) -> None:
        if self._conn is not None:
            return
        self._conn = new_socket_connection(self.addr)


class TcpClientConnection(TcpConnection):
    """Accepted client connection."""

    def __init__(self, conn: Union[ssl.SSLSocket,
                                   socket.socket], addr: Tuple[str, int]):
        super().__init__(tcpConnectionTypes.CLIENT)
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = conn
        self.addr: Tuple[str, int] = addr

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn


class AcceptorPool:
    """AcceptorPool.

    Pre-spawns worker processes to utilize all cores available on the system.  Server socket connection is
    dispatched over a pipe to workers.  Each worker accepts incoming client request and spawns a
    separate thread to handle the client request.
    """

    def __init__(self,
                 hostname: Union[ipaddress.IPv4Address,
                                 ipaddress.IPv6Address],
                 port: int, backlog: int, num_workers: int,
                 work_klass: type, **kwargs: Any) -> None:
        self.running: bool = False

        self.hostname: Union[ipaddress.IPv4Address,
                             ipaddress.IPv6Address] = hostname
        self.port: int = port
        self.family: socket.AddressFamily = socket.AF_INET6 if hostname.version == 6 else socket.AF_INET
        self.backlog: int = backlog
        self.socket: Optional[socket.socket] = None

        self.current_worker_id = 0
        self.num_workers = num_workers
        self.workers: List[Worker] = []
        self.work_queues: List[Tuple[connection.Connection,
                                     connection.Connection]] = []

        self.work_klass = work_klass
        self.kwargs = kwargs

    def listen(self) -> None:
        self.socket = socket.socket(self.family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((str(self.hostname), self.port))
        self.socket.listen(self.backlog)
        self.socket.setblocking(False)
        self.socket.settimeout(0)
        logger.info('Listening on %s:%d' % (self.hostname, self.port))

    def start_workers(self) -> None:
        """Start worker processes."""
        for worker_id in range(self.num_workers):
            work_queue = multiprocessing.Pipe()

            worker = Worker(work_queue[1], self.work_klass, **self.kwargs)
            worker.daemon = True
            worker.start()

            self.workers.append(worker)
            self.work_queues.append(work_queue)
        logger.info('Started %d workers' % self.num_workers)

    def shutdown(self) -> None:
        logger.info('Shutting down %d workers' % self.num_workers)
        for worker in self.workers:
            worker.join()

    def setup(self) -> None:
        """Listen on port, setup workers and pass server socket to workers."""
        self.running = True
        self.listen()
        self.start_workers()

        # Send server socket to workers.
        assert self.socket is not None
        for work_queue in self.work_queues:
            work_queue[0].send(self.family)
            send_handle(work_queue[0], self.socket.fileno(),
                        self.workers[self.current_worker_id].pid)
        self.socket.close()


class Worker(multiprocessing.Process):
    """Socket client acceptor.

    Accepts client connection over received server socket handle and
    starts a new work thread.
    """

    lock = multiprocessing.Lock()

    def __init__(
            self,
            work_queue: connection.Connection,
            work_klass: type,
            **kwargs: Any):
        super().__init__()
        self.work_queue: connection.Connection = work_queue
        self.work_klass = work_klass
        self.kwargs = kwargs

    def run(self) -> None:
        family = self.work_queue.recv()
        sock = socket.fromfd(
            recv_handle(self.work_queue),
            family=family,
            type=socket.SOCK_STREAM
        )
        selector = selectors.DefaultSelector()
        try:
            while True:
                with self.lock:
                    selector.register(sock, selectors.EVENT_READ)
                    events = selector.select(timeout=1)
                    selector.unregister(sock)
                    if len(events) == 0:
                        continue
                try:
                    conn, addr = sock.accept()
                except BlockingIOError:  # as e:
                    # logger.exception('BlockingIOError', exc_info=e)
                    continue
                work = self.work_klass(
                    fileno=conn.fileno(),
                    addr=addr,
                    **self.kwargs)
                work.setDaemon(True)
                work.start()
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()


class ChunkParser:
    """HTTP chunked encoding response parser."""

    def __init__(self) -> None:
        self.state = chunkParserStates.WAITING_FOR_SIZE
        self.body: bytes = b''  # Parsed chunks
        self.chunk: bytes = b''  # Partial chunk received
        # Expected size of next following chunk
        self.size: Optional[int] = None

    def parse(self, raw: bytes) -> None:
        more = True if len(raw) > 0 else False
        while more:
            more, raw = self.process(raw)

    def process(self, raw: bytes) -> Tuple[bool, bytes]:
        if self.state == chunkParserStates.WAITING_FOR_SIZE:
            # Consume prior chunk in buffer
            # in case chunk size without CRLF was received
            raw = self.chunk + raw
            self.chunk = b''
            # Extract following chunk data size
            line, raw = find_http_line(raw)
            # CRLF not received or Blank line was received.
            if line is None or line.strip() == b'':
                self.chunk = raw
                raw = b''
            else:
                self.size = int(line, 16)
                self.state = chunkParserStates.WAITING_FOR_DATA
        elif self.state == chunkParserStates.WAITING_FOR_DATA:
            assert self.size is not None
            remaining = self.size - len(self.chunk)
            self.chunk += raw[:remaining]
            raw = raw[remaining:]
            if len(self.chunk) == self.size:
                raw = raw[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = chunkParserStates.COMPLETE
                else:
                    self.state = chunkParserStates.WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(raw) > 0, raw


class HttpParser:
    """HTTP request/response parser."""

    def __init__(self, parser_type: int) -> None:
        self.type: int = parser_type
        self.state: int = httpParserStates.INITIALIZED

        # Raw bytes as passed to parse(raw) method and its total size
        self.bytes: bytes = b''
        self.total_size: int = 0

        # Buffer to hold unprocessed bytes
        self.buffer: bytes = b''

        self.headers: Dict[bytes, Tuple[bytes, bytes]] = dict()
        self.body: Optional[bytes] = None

        self.method: Optional[bytes] = None
        self.url: Optional[urlparse.SplitResultBytes] = None
        self.code: Optional[bytes] = None
        self.reason: Optional[bytes] = None
        self.version: Optional[bytes] = None

        self.chunk_parser: Optional[ChunkParser] = None

        # This cleans up developer APIs as Python urlparse.urlsplit behaves differently
        # for incoming proxy request and incoming web request.  Web request is the one
        # which is broken.
        self.host: Optional[bytes] = None
        self.port: Optional[int] = None

    def header(self, key: bytes) -> bytes:
        if key.lower() not in self.headers:
            raise KeyError('%s not found in headers', text_(key))
        return self.headers[key.lower()][1]

    def has_header(self, key: bytes) -> bool:
        return key.lower() in self.headers

    def add_header(self, key: bytes, value: bytes) -> None:
        self.headers[key.lower()] = (key, value)

    def add_headers(self, headers: List[Tuple[bytes, bytes]]) -> None:
        for (key, value) in headers:
            self.add_header(key, value)

    def del_header(self, header: bytes) -> None:
        if header.lower() in self.headers:
            del self.headers[header.lower()]

    def del_headers(self, headers: List[bytes]) -> None:
        for key in headers:
            self.del_header(key.lower())

    def set_host_port(self) -> None:
        if self.type == httpParserTypes.REQUEST_PARSER:
            if self.method == b'CONNECT' and self.url:
                u = urlparse.urlsplit(b'//' + self.url.path)
                self.host, self.port = u.hostname, u.port
            elif self.url:
                self.host, self.port = self.url.hostname, self.url.port \
                    if self.url.port else 80
            else:
                raise Exception('Invalid request\n%s' % self.bytes)

    def is_chunked_encoded_response(self) -> bool:
        return self.type == httpParserTypes.RESPONSE_PARSER and b'transfer-encoding' in self.headers and \
            self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    def parse(self, raw: bytes) -> None:
        """Parses Http request out of raw bytes.

        Check HttpParser state after parse has successfully returned."""
        self.bytes += raw
        self.total_size += len(raw)

        # Prepend past buffer
        raw = self.buffer + raw
        self.buffer = b''

        more = True if len(raw) > 0 else False
        while more:
            if self.state in (
                    httpParserStates.HEADERS_COMPLETE,
                    httpParserStates.RCVING_BODY,
                    httpParserStates.COMPLETE) and (
                    self.method == b'POST' or self.type == httpParserTypes.RESPONSE_PARSER):
                if not self.body:
                    self.body = b''

                if b'content-length' in self.headers:
                    self.state = httpParserStates.RCVING_BODY
                    self.body += raw
                    if self.body and \
                            len(self.body) >= int(self.headers[b'content-length'][1]):
                        self.state = httpParserStates.COMPLETE
                elif self.is_chunked_encoded_response():
                    if not self.chunk_parser:
                        self.chunk_parser = ChunkParser()
                    self.chunk_parser.parse(raw)
                    if self.chunk_parser.state == chunkParserStates.COMPLETE:
                        self.body = self.chunk_parser.body
                        self.state = httpParserStates.COMPLETE

                more, raw = False, b''
            else:
                more, raw = self.process(raw)
        self.buffer = raw

    def process(self, raw: bytes) -> Tuple[bool, bytes]:
        """Returns False when no CRLF could be found in received bytes."""
        line, raw = find_http_line(raw)
        if line is None:
            return False, raw

        if self.state == httpParserStates.INITIALIZED:
            self.process_line(line)
            self.state = httpParserStates.LINE_RCVD
        elif self.state in (httpParserStates.LINE_RCVD, httpParserStates.RCVING_HEADERS):
            if self.state == httpParserStates.LINE_RCVD:
                # LINE_RCVD state is equivalent to RCVING_HEADERS
                self.state = httpParserStates.RCVING_HEADERS
            if line.strip() == b'':  # Blank line received.
                self.state = httpParserStates.HEADERS_COMPLETE
            else:
                self.process_header(line)

        # When connect request is received without a following host header
        # See
        # `TestHttpParser.test_connect_request_without_host_header_request_parse`
        # for details
        if self.state == httpParserStates.LINE_RCVD and \
                self.type == httpParserTypes.RESPONSE_PARSER and \
                raw == CRLF:
            self.state = httpParserStates.COMPLETE
        # When raw request has ended with \r\n\r\n and no more http headers are expected
        # See `TestHttpParser.test_request_parse_without_content_length` and
        # `TestHttpParser.test_response_parse_without_content_length` for details
        elif self.state == httpParserStates.HEADERS_COMPLETE and \
                self.type == httpParserTypes.REQUEST_PARSER and \
                self.method != b'POST' and \
                self.bytes.endswith(CRLF * 2):
            self.state = httpParserStates.COMPLETE
        elif self.state == httpParserStates.HEADERS_COMPLETE and \
                self.type == httpParserTypes.REQUEST_PARSER and \
                self.method == b'POST' and \
                (b'content-length' not in self.headers or
                 (b'content-length' in self.headers and
                  int(self.headers[b'content-length'][1]) == 0)) and \
                self.bytes.endswith(CRLF * 2):
            self.state = httpParserStates.COMPLETE

        return len(raw) > 0, raw

    def process_line(self, raw: bytes) -> None:
        line = raw.split(WHITESPACE)
        if self.type == httpParserTypes.REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = WHITESPACE.join(line[2:])
        self.set_host_port()

    def process_header(self, raw: bytes) -> None:
        parts = raw.split(COLON)
        key = parts[0].strip()
        value = COLON.join(parts[1:]).strip()
        self.add_headers([(key, value)])

    def build_url(self) -> bytes:
        if not self.url:
            return b'/None'

        url = self.url.path
        if url == b'':
            url = b'/'
        if not self.url.query == b'':
            url += b'?' + self.url.query
        if not self.url.fragment == b'':
            url += b'#' + self.url.fragment
        return url

    def build(self, disable_headers: Optional[List[bytes]] = None) -> bytes:
        assert self.method and self.version
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        return build_http_request(
            self.method, self.build_url(), self.version,
            headers={} if not self.headers else {self.headers[k][0]: self.headers[k][1] for k in self.headers if
                                                 k.lower() not in disable_headers},
            body=self.body
        )

    ##########################################################################
    # HttpParser was originally written to parse the incoming raw Http requests.
    # Since request / response objects passed to ProtocolHandlerPlugin methods
    # are also HttpParser objects, methods below were added to simplify developer API.
    ##########################################################################

    def has_upstream_server(self) -> bool:
        """Host field SHOULD be None for incoming local WebServer requests."""
        return True if self.host is not None else False


class ProtocolException(Exception):
    """Top level ProtocolException exception class.

    All exceptions raised during execution of Http request lifecycle MUST
    inherit ProtocolException base class. Implement response() method
    to optionally return custom response to client."""

    def response(self, request: HttpParser) -> Optional[bytes]:
        pass  # pragma: no cover


class HttpRequestRejected(ProtocolException):
    """Generic exception that can be used to reject the client requests.

    Connections can either be dropped/closed or optionally an
    HTTP status code can be returned."""

    def __init__(self,
                 status_code: Optional[int] = None,
                 reason: Optional[bytes] = None,
                 body: Optional[bytes] = None):
        self.status_code: Optional[int] = status_code
        self.reason: Optional[bytes] = reason
        self.body: Optional[bytes] = body

    def response(self, _request: HttpParser) -> Optional[bytes]:
        pkt = []
        if self.status_code is not None:
            line = b'HTTP/1.1 ' + bytes_(self.status_code)
            if self.reason:
                line += WHITESPACE + self.reason
            pkt.append(line)
            pkt.append(PROXY_AGENT_HEADER)
        if self.body:
            pkt.append(b'Content-Length: ' + bytes_(len(self.body)))
            pkt.append(CRLF)
            pkt.append(self.body)
        else:
            if len(pkt) > 0:
                pkt.append(CRLF)
        return CRLF.join(pkt) if len(pkt) > 0 else None


class ProxyConnectionFailed(ProtocolException):
    """Exception raised when HttpProxyPlugin is unable to establish connection to upstream server."""

    RESPONSE_PKT = build_http_response(
        502, reason=b'Bad Gateway',
        headers={PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'},
        body=b'Bad Gateway'
    )

    def __init__(self, host: str, port: int, reason: str):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT

    def __str__(self) -> str:
        return '<ProxyConnectionFailed - %s:%s - %s>' % (
            self.host, self.port, self.reason)


class ProxyAuthenticationFailed(ProtocolException):
    """Exception raised when Http Proxy auth is enabled and
    incoming request doesn't present necessary credentials."""

    RESPONSE_PKT = build_http_response(
        407, reason=b'Proxy Authentication Required',
        headers={PROXY_AGENT_HEADER_KEY: PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close',
                 b'Proxy-Authenticate': b'Basic'},
        body=b'Proxy Authentication Required')

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT


if TYPE_CHECKING:
    DevtoolsEventQueueType = queue.Queue[Dict[str, Any]]
else:
    DevtoolsEventQueueType = queue.Queue


class ProtocolConfig:
    """Holds various configuration values applicable to ProtocolHandler.

    This config class helps us avoid passing around bunch of key/value pairs across methods.
    """

    ROOT_DATA_DIR_NAME = '.proxy.py'
    GENERATED_CERTS_DIR_NAME = 'certificates'

    def __init__(
            self,
            auth_code: Optional[bytes] = DEFAULT_BASIC_AUTH,
            server_recvbuf_size: int = DEFAULT_SERVER_RECVBUF_SIZE,
            client_recvbuf_size: int = DEFAULT_CLIENT_RECVBUF_SIZE,
            pac_file: Optional[str] = DEFAULT_PAC_FILE,
            pac_file_url_path: Optional[bytes] = DEFAULT_PAC_FILE_URL_PATH,
            plugins: Optional[Dict[bytes, List[type]]] = None,
            disable_headers: Optional[List[bytes]] = None,
            certfile: Optional[str] = None,
            keyfile: Optional[str] = None,
            ca_cert_dir: Optional[str] = None,
            ca_key_file: Optional[str] = None,
            ca_cert_file: Optional[str] = None,
            ca_signing_key_file: Optional[str] = None,
            num_workers: int = 0,
            hostname: Union[ipaddress.IPv4Address,
                            ipaddress.IPv6Address] = DEFAULT_IPV6_HOSTNAME,
            port: int = DEFAULT_PORT,
            backlog: int = DEFAULT_BACKLOG,
            static_server_dir: str = DEFAULT_STATIC_SERVER_DIR,
            enable_static_server: bool = DEFAULT_ENABLE_STATIC_SERVER,
            devtools_event_queue: Optional[DevtoolsEventQueueType] = None) -> None:
        self.auth_code = auth_code
        self.server_recvbuf_size = server_recvbuf_size
        self.client_recvbuf_size = client_recvbuf_size
        self.pac_file = pac_file
        self.pac_file_url_path = pac_file_url_path
        if plugins is None:
            plugins = {}
        self.plugins: Dict[bytes, List[type]] = plugins
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        self.disable_headers = disable_headers
        self.certfile: Optional[str] = certfile
        self.keyfile: Optional[str] = keyfile
        self.ca_key_file: Optional[str] = ca_key_file
        self.ca_cert_file: Optional[str] = ca_cert_file
        self.ca_signing_key_file: Optional[str] = ca_signing_key_file
        self.num_workers: int = num_workers
        self.hostname: Union[ipaddress.IPv4Address,
                             ipaddress.IPv6Address] = hostname
        self.port: int = port
        self.backlog: int = backlog

        self.enable_static_server: bool = enable_static_server
        self.static_server_dir: str = static_server_dir
        self.devtools_event_queue = devtools_event_queue

        self.proxy_py_data_dir = os.path.join(
            str(pathlib.Path.home()), self.ROOT_DATA_DIR_NAME)
        os.makedirs(self.proxy_py_data_dir, exist_ok=True)

        self.ca_cert_dir: Optional[str] = ca_cert_dir
        if self.ca_cert_dir is None:
            self.ca_cert_dir = os.path.join(
                self.proxy_py_data_dir, self.GENERATED_CERTS_DIR_NAME)
            os.makedirs(self.ca_cert_dir, exist_ok=True)


class ProtocolHandlerPlugin(ABC):
    """Base ProtocolHandler Plugin class.

    NOTE: This is an internal plugin and in most cases only useful for core contributors.
    If you are looking for proxy server plugins see `<proxy.HttpProxyBasePlugin>`.

    Implements various lifecycle events for an accepted client connection.
    Following events are of interest:

    1. Client Connection Accepted
       A new plugin instance is created per accepted client connection.
       Add your logic within __init__ constructor for any per connection setup.
    2. Client Request Chunk Received
       on_client_data is called for every chunk of data sent by the client.
    3. Client Request Complete
       on_request_complete is called once client request has completed.
    4. Server Response Chunk Received
       on_response_chunk is called for every chunk received from the server.
    5. Client Connection Closed
       Add your logic within `on_client_connection_close` for any per connection teardown.
    """

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        self.config: ProtocolConfig = config
        self.client: TcpClientConnection = client
        self.request: HttpParser = request
        super().__init__()

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__

    @abstractmethod
    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []  # pragma: no cover

    @abstractmethod
    def write_to_descriptors(self, w: List[Union[int, _HasFileno]]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def read_from_descriptors(self, r: List[Union[int, _HasFileno]]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw  # pragma: no cover

    @abstractmethod
    def on_request_complete(self) -> Union[socket.socket, bool]:
        """Called right after client request parser has reached COMPLETE state."""
        pass  # pragma: no cover

    @abstractmethod
    def on_response_chunk(self, chunk: bytes) -> bytes:
        """Handle data chunks as received from the server.

        Return optionally modified chunk to return back to client."""
        return chunk  # pragma: no cover

    @abstractmethod
    def on_client_connection_close(self) -> None:
        pass  # pragma: no cover


class HttpProxyBasePlugin(ABC):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        self.config = config
        self.client = client
        self.request = request

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__

    @abstractmethod
    def before_upstream_connection(self) -> bool:
        """Handler called just before Proxy upstream connection is established.

        Raise HttpRequestRejected to drop the connection."""
        pass  # pragma: no cover

    @abstractmethod
    def on_upstream_connection(self) -> None:
        """Handler called right after upstream connection has been established."""
        pass  # pragma: no cover

    @abstractmethod
    def handle_upstream_response(self, raw: bytes) -> bytes:
        """Handled called right after reading response from upstream server and
        before queuing that response to client.

        Optionally return modified response to queue for client."""
        return raw  # pragma: no cover

    @abstractmethod
    def on_upstream_connection_close(self) -> None:
        """Handler called right after upstream connection has been closed."""
        pass  # pragma: no cover


class HttpProxyPlugin(ProtocolHandlerPlugin):
    """ProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = build_http_response(
        200, reason=b'Connection established'
    )

    # Used to synchronize with other HttpProxyPlugin instances while
    # generating certificates
    lock = threading.Lock()

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        super().__init__(config, client, request)
        self.server: Optional[TcpServerConnection] = None
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)

        self.plugins: Dict[str, HttpProxyBasePlugin] = {}
        if b'HttpProxyBasePlugin' in self.config.plugins:
            for klass in self.config.plugins[b'HttpProxyBasePlugin']:
                instance = klass(self.config, self.client, self.request)
                self.plugins[instance.name()] = instance

    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.request.has_upstream_server():
            return [], []

        r: List[socket.socket] = []
        w: List[socket.socket] = []
        if self.server and not self.server.closed and self.server.connection:
            r.append(self.server.connection)
        if self.server and not self.server.closed and \
                self.server.has_buffer() and self.server.connection:
            w.append(self.server.connection)
        return r, w

    def write_to_descriptors(self, w: List[Union[int, _HasFileno]]) -> bool:
        if self.request.has_upstream_server() and \
                self.server and not self.server.closed and \
                self.server.buffer_size() > 0 and \
                self.server.connection in w:
            logger.debug('Server is write ready, flushing buffer')
            try:
                self.server.flush()
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for server')
                return True
        return False

    def read_from_descriptors(self, r: List[Union[int, _HasFileno]]) -> bool:
        if self.request.has_upstream_server(
        ) and self.server and not self.server.closed and self.server.connection in r:
            logger.debug('Server is ready for reads, reading')
            raw = self.server.recv(self.config.server_recvbuf_size)
            # self.last_activity = ProtocolHandler.now()
            if not raw:
                logger.debug('Server closed connection, tearing down...')
                return True

            for plugin in self.plugins.values():
                raw = plugin.handle_upstream_response(raw)

            # parse incoming response packet
            # only for non-https requests
            if not self.request.method == b'CONNECT':
                self.response.parse(raw)
            else:
                self.response.total_size += len(raw)
            # queue raw data for client
            self.client.queue(raw)
        return False

    def on_client_connection_close(self) -> None:
        if not self.request.has_upstream_server():
            return
        server_host, server_port = self.server.addr if self.server else (
            None, None)
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s - %s bytes' %
                (self.client.addr[0],
                 self.client.addr[1],
                 text_(
                     self.request.method),
                 text_(server_host),
                 text_(server_port),
                 self.response.total_size))
        elif self.request.method:
            logger.info(
                '%s:%s - %s %s:%s%s - %s %s - %s bytes' %
                (self.client.addr[0], self.client.addr[1],
                 text_(self.request.method),
                 text_(server_host), server_port,
                 text_(self.request.build_url()),
                 text_(self.response.code),
                 text_(self.response.reason),
                 self.response.total_size))
        # Invoke plugin.on_upstream_connection_close
        if self.server and not self.server.closed:
            for plugin in self.plugins.values():
                plugin.on_upstream_connection_close()
            self.server.close()
            logger.debug(
                'Closed server connection with pending server buffer size %d bytes' %
                self.server.buffer_size())

    def on_response_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        if not self.request.has_upstream_server():
            return raw

        if self.server and not self.server.closed:
            self.server.queue(raw)
            return None
        else:
            return raw

    def generate_upstream_certificate(self) -> Optional[str]:
        if self.config.ca_cert_dir and self.config.ca_signing_key_file and \
                self.config.ca_cert_file and self.config.ca_key_file:
            with self.lock:
                cert_file_path = os.path.join(
                    self.config.ca_cert_dir,
                    '%s.pem' %
                    text_(
                        self.request.host))
                if not os.path.isfile(cert_file_path):
                    logger.debug('Generating certificates %s', cert_file_path)
                    # TODO: Use ssl.get_server_certificate to populate generated certificate metadata
                    # Currently we only set CN= field for generated certificates.
                    gen_cert = subprocess.Popen(
                        ['/usr/bin/openssl', 'req', '-new', '-key', self.config.ca_signing_key_file, '-subj',
                         '/CN=%s' % text_(self.request.host)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
                    sign_cert = subprocess.Popen(
                        ['/usr/bin/openssl', 'x509', '-req', '-days', '365', '-CA', self.config.ca_cert_file, '-CAkey',
                         self.config.ca_key_file, '-set_serial', str(int(time.time())), '-out', cert_file_path],
                        stdin=gen_cert.stdout,
                        stderr=subprocess.PIPE)
                    # TODO: Ensure sign_cert success.
                    sign_cert.communicate(timeout=10)
                return cert_file_path
        else:
            return None

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if not self.request.has_upstream_server():
            return False

        # Note: can raise HttpRequestRejected exception
        for plugin in self.plugins.values():
            teardown = plugin.before_upstream_connection()
            if teardown:
                return teardown

        self.authenticate()
        self.connect_upstream()

        for plugin in self.plugins.values():
            plugin.on_upstream_connection()

        if self.request.method == b'CONNECT':
            self.client.queue(
                HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
            # If interception is enabled, generate server certificates
            if self.config.ca_key_file and self.config.ca_cert_file and self.config.ca_signing_key_file:
                # Flush client buffer before wrapping,
                # but is client ready for writes?
                self.client.flush()
                generated_cert = self.generate_upstream_certificate()
                if generated_cert:
                    if not (self.config.keyfile and self.config.certfile) and \
                            self.server and isinstance(self.server.connection, socket.socket):
                        self.client._conn = ssl.wrap_socket(
                            self.client.connection,
                            server_side=True,
                            keyfile=self.config.ca_signing_key_file,
                            certfile=generated_cert)
                        # Wrap our connection to upstream server connection
                        ctx = ssl.create_default_context(
                            ssl.Purpose.SERVER_AUTH)
                        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                        self.server._conn = ctx.wrap_socket(
                            self.server.connection,
                            server_hostname=text_(self.request.host))
                        logger.info(
                            'TLS interception using %s', generated_cert)
                        return self.client.connection
        elif self.server:
            # - proxy-connection header is a mistake, it doesn't seem to be
            #   officially documented in any specification, drop it.
            # - proxy-authorization is of no use for upstream, remove it.
            self.request.del_headers(
                [b'proxy-authorization', b'proxy-connection'])
            # - For HTTP/1.0, connection header defaults to close
            # - For HTTP/1.1, connection header defaults to keep-alive
            # Respect headers sent by client instead of manipulating
            # Connection or Keep-Alive header.  However, note that per
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
            # connection headers are meant for communication between client and
            # first intercepting proxy.
            self.request.add_headers([(b'Via', b'1.1 proxy.py v%s' % version)])
            # Disable args.disable_headers before dispatching to upstream
            self.server.queue(
                self.request.build(
                    disable_headers=self.config.disable_headers))
        return False

    def authenticate(self) -> None:
        if self.config.auth_code:
            if b'proxy-authorization' not in self.request.headers or \
                    self.request.headers[b'proxy-authorization'][1] != self.config.auth_code:
                raise ProxyAuthenticationFailed()

    def connect_upstream(self) -> None:
        host, port = self.request.host, self.request.port
        if host and port:
            self.server = TcpServerConnection(text_(host), port)
            try:
                logger.debug(
                    'Connecting to upstream %s:%s' %
                    (text_(host), port))
                self.server.connect()
                logger.debug(
                    'Connected to upstream %s:%s' %
                    (text_(host), port))
            except Exception as e:  # TimeoutError, socket.gaierror
                self.server.closed = True
                raise ProxyConnectionFailed(text_(host), port, repr(e)) from e
        else:
            logger.exception('Both host and port must exist')
            raise ProtocolException()


class WebsocketFrame:
    """Websocket frames parser and constructor."""

    GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    def __init__(self) -> None:
        self.reset()

    def reset(self):
        self.fin: bool = False
        self.rsv1: bool = False
        self.rsv2: bool = False
        self.rsv3: bool = False
        self.opcode: int = 0
        self.masked: bool = False
        self.payload_length: Optional[int] = None
        self.mask: Optional[bytes] = None
        self.data: Optional[bytes] = None

    def parse_fin_and_rsv(self, byte: int) -> None:
        self.fin = bool(byte & 1 << 7)
        self.rsv1 = bool(byte & 1 << 6)
        self.rsv2 = bool(byte & 1 << 5)
        self.rsv3 = bool(byte & 1 << 4)
        self.opcode = byte & 0b00001111

    def parse_mask_and_payload(self, byte: int) -> None:
        self.masked = bool(byte & 0b10000000)
        self.payload_length = byte & 0b01111111

    def build(self) -> bytes:
        if self.payload_length is None and self.data:
            self.payload_length = len(self.data)
        raw = io.BytesIO()
        raw.write(
            struct.pack(
                '!B',
                (1 << 7 if self.fin else 0) |
                (1 << 6 if self.rsv1 else 0) |
                (1 << 5 if self.rsv2 else 0) |
                (1 << 4 if self.rsv3 else 0) |
                self.opcode
            ))
        assert self.payload_length is not None
        if self.payload_length < 126:
            raw.write(
                struct.pack(
                    '!B',
                    (1 << 7 if self.masked else 0) | self.payload_length
                )
            )
        elif self.payload_length < 1 << 16:
            raw.write(
                struct.pack(
                    '!BH',
                    (1 << 7 if self.masked else 0) | 126,
                    self.payload_length
                )
            )
        elif self.payload_length < 1 << 64:
            raw.write(
                struct.pack(
                    '!BHQ',
                    (1 << 7 if self.masked else 0) | 127,
                    self.payload_length
                )
            )
        else:
            raise ValueError(f'Invalid payload_length { self.payload_length },'
                             f'maximum allowed { 1 << 64 }')
        if self.masked and self.data:
            mask = secrets.token_bytes(4) if self.mask is None else self.mask
            raw.write(mask)
            raw.write(self.apply_mask(self.data, mask))
        elif self.data:
            raw.write(self.data)
        return raw.getvalue()

    def parse(self, raw: bytes) -> bytes:
        cur = 0
        self.parse_fin_and_rsv(raw[cur])
        cur += 1

        self.parse_mask_and_payload(raw[cur])
        cur += 1

        if self.payload_length == 126:
            data = raw[cur: cur + 2]
            self.payload_length, = struct.unpack('!H', data)
            cur += 2
        elif self.payload_length == 127:
            data = raw[cur: cur + 8]
            self.payload_length, = struct.unpack('!Q', data)
            cur += 8

        if self.masked:
            self.mask = raw[cur: cur + 4]
            cur += 4

        self.data = raw[cur: cur + self.payload_length]
        cur += self.payload_length
        if self.masked:
            assert self.mask is not None
            self.data = self.apply_mask(self.data, self.mask)

        return raw[cur:]

    @staticmethod
    def apply_mask(data: bytes, mask: bytes) -> bytes:
        raw = bytearray(data)
        for i in range(len(raw)):
            raw[i] = raw[i] ^ mask[i % 4]
        return bytes(raw)

    @staticmethod
    def key_to_accept(key: bytes) -> bytes:
        sha1 = hashlib.sha1()
        sha1.update(key + WebsocketFrame.GUID)
        return base64.b64encode(sha1.digest())


class WebsocketClient(TcpConnection):

    def __init__(self,
                 hostname: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                 port: int,
                 path: bytes = b'/',
                 on_message: Optional[Callable[[WebsocketFrame], None]] = None) -> None:
        super().__init__(tcpConnectionTypes.CLIENT)
        self.hostname: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = hostname
        self.port: int = port
        self.path: bytes = path
        self.sock: socket.socket = new_socket_connection((str(self.hostname), self.port))
        self.on_message: Optional[Callable[[WebsocketFrame], None]] = on_message
        self.upgrade()
        self.sock.setblocking(False)
        self.selector: selectors.DefaultSelector = selectors.DefaultSelector()

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        return self.sock

    def upgrade(self) -> None:
        key = base64.b64encode(secrets.token_bytes(16))
        self.sock.send(build_websocket_handshake_request(key, url=self.path))
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(self.sock.recv(DEFAULT_BUFFER_SIZE))
        accept = response.header(b'Sec-Websocket-Accept')
        assert WebsocketFrame.key_to_accept(key) == accept

    def ping(self, data: Optional[bytes] = None) -> None:
        pass

    def pong(self, data: Optional[bytes] = None) -> None:
        pass

    def shutdown(self, data: Optional[bytes] = None) -> None:
        """Closes connection with the server."""
        super().close()

    def run_once(self) -> bool:
        ev = selectors.EVENT_READ
        if self.has_buffer():
            ev |= selectors.EVENT_WRITE
        self.selector.register(self.sock.fileno(), ev)
        events = self.selector.select(timeout=1)
        self.selector.unregister(self.sock)
        for key, mask in events:
            if mask & selectors.EVENT_READ and self.on_message:
                raw = self.recv()
                if raw is None or raw == b'':
                    self.closed = True
                    logger.debug('Websocket connection closed by server')
                    return True
                frame = WebsocketFrame()
                frame.parse(raw)
                self.on_message(frame)
            elif mask & selectors.EVENT_WRITE:
                logger.debug(self.buffer)
                self.flush()
        return False

    def run(self) -> None:
        logger.debug('running')
        try:
            while not self.closed:
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.selector.unregister(self.sock)
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                logging.exception('Exception while shutdown of websocket client', exc_info=e)
            self.sock.close()
        logger.info('done')


class HttpWebServerBasePlugin(ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection):
        self.config = config
        self.client = client

    @abstractmethod
    def routes(self) -> List[Tuple[int, bytes]]:
        """Return List(protocol, path) that this plugin handles."""
        raise NotImplementedError()

    @abstractmethod
    def handle_request(self, request: HttpParser) -> None:
        """Handle the request and serve response."""
        raise NotImplementedError()

    @abstractmethod
    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Handle websocket frame."""
        raise NotImplementedError()


class DevtoolsFrontendPlugin(HttpWebServerBasePlugin):

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection):
        self.event_dispatcher_thread = threading.Thread(
            target=DevtoolsFrontendPlugin.event_dispatcher,
            args=(config, client))
        self.event_dispatcher_thread.setDaemon(True)
        self.event_dispatcher_thread.start()
        super().__init__(config, client)

    @staticmethod
    def event_dispatcher(config: ProtocolConfig, client: TcpClientConnection):
        while True:
            try:
                ev = config.devtools_event_queue.get(timeout=1)
                frame = WebsocketFrame()
                frame.fin = True
                frame.opcode = websocketOpcodes.TEXT_FRAME
                frame.data = bytes_(json.dumps(ev))
                client.queue(frame.build())
            except queue.Empty:
                pass
            except Exception as e:
                logger.exception('Event dispatcher exception', exc_info=e)
                break
            except KeyboardInterrupt:
                break

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.WEBSOCKET, b'/devtools')
        ]

    def handle_request(self, request: HttpParser) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        if frame.data:
            message = json.loads(frame.data)
            self.handle_message(message)
        else:
            logger.debug('No data found in frame')

    def handle_message(self, message) -> None:
        frame = WebsocketFrame()
        frame.fin = True
        frame.opcode = websocketOpcodes.TEXT_FRAME

        if message['method'] in (
            'Page.canScreencast',
            'Network.canEmulateNetworkConditions',
            'Emulation.canEmulate'
        ):
            data = json.dumps({
                'id': message['id'],
                'result': False
            })
        elif message['method'] == 'Page.getResourceTree':
            data = json.dumps({
                'id': message['id'],
                'result': {
                    'frameTree': {
                        'frame': {
                            'id': 1,
                            'url': 'http://proxypy',
                            'mimeType': 'other',
                        },
                        'childFrames': [],
                        'resources': []
                    }
                }
            })
        elif message['method'] == 'Network.getResponseBody':
            logger.debug('received request method Network.getResponseBody')
            data = json.dumps({
                'id': message['id'],
                'result': {}
            })
        else:
            data = json.dumps({
                'id': message['id'],
                'result': {},
            })

        frame.data = bytes_(data)
        self.client.queue(frame.build())


class HttpWebServerPacFilePlugin(HttpWebServerBasePlugin):

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection):
        super().__init__(config, client)
        self.pac_file_response: Optional[bytes] = None
        self.cache_pac_file_response()

    def routes(self) -> List[Tuple[int, bytes]]:
        if self.config.pac_file_url_path:
            return [(httpProtocolTypes.HTTP, bytes_(
                self.config.pac_file_url_path))]
        return []

    def handle_request(self, request: Union[HttpParser, WebsocketFrame]) -> None:
        if self.config.pac_file and self.pac_file_response:
            self.client.queue(self.pac_file_response)
            self.client.flush()

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def cache_pac_file_response(self) -> None:
        if self.config.pac_file:
            try:
                with open(self.config.pac_file, 'rb') as f:
                    content = f.read()
            except IOError:
                content = bytes_(self.config.pac_file)
            self.pac_file_response = build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                    b'Connection': b'close'
                }, body=content
            )


class HttpWebServerPlugin(ProtocolHandlerPlugin):
    """ProtocolHandler plugin which handles incoming requests to local web server."""

    DEFAULT_404_RESPONSE = build_http_response(
        404, reason=b'NOT FOUND',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    )

    DEFAULT_501_RESPONSE = build_http_response(
        501, reason=b'NOT IMPLEMENTED',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    )

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        super().__init__(config, client, request)

        self.switched_protocol: Optional[int] = None

        self.routes: Dict[int, Dict[bytes, HttpWebServerBasePlugin]] = {
            httpProtocolTypes.HTTP: {},
            httpProtocolTypes.HTTPS: {},
            httpProtocolTypes.WEBSOCKET: {},
        }

        if b'HttpWebServerBasePlugin' in self.config.plugins:
            for klass in self.config.plugins[b'HttpWebServerBasePlugin']:
                instance = klass(self.config, self.client)
                for (protocol, path) in instance.routes():
                    self.routes[protocol][path] = instance

    def serve_file_or_404(self, path: str) -> None:
        try:
            with open(path, 'rb') as f:
                content = f.read()
            content_type = mimetypes.guess_type(path)[0]
            if content_type is None:
                content_type = 'text/plain'
            self.client.queue(build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': bytes_(content_type),
                    b'Connection': b'close'
                }, body=content
            ))
        except IOError:
            self.client.queue(self.DEFAULT_404_RESPONSE)
        finally:
            self.client.flush()

    def try_upgrade(self) -> bool:
        if self.request.has_header(b'connection') and \
                self.request.header(b'connection').lower() == b'upgrade':
            if self.request.has_header(b'upgrade') and \
                    self.request.header(b'upgrade').lower() == b'websocket':
                self.client.queue(
                    build_websocket_handshake_response(
                        WebsocketFrame.key_to_accept(
                            self.request.header(b'Sec-WebSocket-Key'))))
                self.client.flush()
                self.switched_protocol = httpProtocolTypes.WEBSOCKET
            else:
                self.client.queue(self.DEFAULT_501_RESPONSE)
                self.client.flush()
                return True
        return False

    def route_by_protocol(self,
                          url: bytes, protocol: int,
                          request: Optional[HttpParser] = None,
                          frame: Optional[WebsocketFrame] = None) -> bool:
        for route_ in self.routes[protocol]:
            if route_ == url:
                if request:
                    self.routes[protocol][route_].handle_request(request)
                elif frame:
                    self.routes[protocol][route_].on_websocket_message(frame)
                self.client.flush()
                return True
        return False

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if self.request.has_upstream_server():
            return False

        url = self.request.build_url()

        # Connection upgrade
        teardown = self.try_upgrade()
        if teardown:
            return True

        # For upgraded connections, nothing more to do
        if self.switched_protocol:
            return False

        # Routing for Http(s) requests
        teardown = self.route_by_protocol(
            url, httpProtocolTypes.HTTPS
            if self.request.method == b'CONNECT'
            else httpProtocolTypes.HTTP,
            request=self.request)
        if teardown:
            return True

        # No-route found, try static serving if enabled
        if self.config.enable_static_server:
            path = text_(url).split('?')[0]
            if os.path.isfile(DEFAULT_STATIC_SERVER_DIR + path):
                self.serve_file_or_404(DEFAULT_STATIC_SERVER_DIR + path)
                return True

        # Catch all unhandled web server requests, return 404
        self.client.queue(self.DEFAULT_404_RESPONSE)
        self.client.flush()
        return True

    def write_to_descriptors(self, w: List[Union[int, _HasFileno]]) -> bool:
        pass

    def read_from_descriptors(self, r: List[Union[int, _HasFileno]]) -> bool:
        pass

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        if self.switched_protocol == httpProtocolTypes.WEBSOCKET:
            remaining = raw
            frame = WebsocketFrame()
            while remaining != b'':
                # TODO: Teardown if invalid protocol exception
                remaining = frame.parse(remaining)
                self.route_by_protocol(
                    self.request.build_url(),
                    httpProtocolTypes.WEBSOCKET,
                    frame=frame)
                frame.reset()
            return None
        return raw

    def on_response_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_client_connection_close(self) -> None:
        if self.request.has_upstream_server():
            return
        logger.info(
            '%s:%s - %s %s' %
            (self.client.addr[0], self.client.addr[1], text_(
                self.request.method), text_(
                self.request.build_url())))

    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []


class ProtocolHandler(threading.Thread):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection object and manages ProtocolHandlerPlugin invocations.
    """

    def __init__(self, fileno: int, addr: Tuple[str, int],
                 config: Optional[ProtocolConfig] = None):
        super().__init__()
        self.start_time: datetime.datetime = self.now()
        self.last_activity: datetime.datetime = self.start_time

        self.config: ProtocolConfig = config if config else ProtocolConfig()
        self.request: HttpParser = HttpParser(httpParserTypes.REQUEST_PARSER)
        self.response: HttpParser = HttpParser(httpParserTypes.RESPONSE_PARSER)

        self.selector = selectors.DefaultSelector()

        conn = self.optionally_wrap_socket(self.fromfd(fileno))
        if conn is None:
            raise TcpConnectionUninitializedException()
        conn.setblocking(False)

        self.client: TcpClientConnection = \
            TcpClientConnection(conn=conn, addr=addr)

        self.plugins: Dict[str, ProtocolHandlerPlugin] = {}
        if b'ProtocolHandlerPlugin' in self.config.plugins:
            for klass in self.config.plugins[b'ProtocolHandlerPlugin']:
                instance = klass(self.config, self.client, self.request)
                self.plugins[instance.name()] = instance

    @staticmethod
    def now() -> datetime.datetime:
        return datetime.datetime.utcnow()

    def fromfd(self, fileno: int) -> socket.socket:
        return socket.fromfd(
            fileno, family=socket.AF_INET if self.config.hostname.version == 4 else socket.AF_INET6,
            type=socket.SOCK_STREAM)

    def optionally_wrap_socket(
            self, conn: socket.socket) -> Optional[Union[ssl.SSLSocket, socket.socket]]:
        """Attempts to wrap accepted client connection using provided certificates.

        Shutdown and closes client connection upon error.
        """
        if self.config.certfile and self.config.keyfile:
            try:
                ctx = ssl.create_default_context(
                    ssl.Purpose.CLIENT_AUTH)
                ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                ctx.verify_mode = ssl.CERT_NONE
                ctx.load_cert_chain(
                    certfile=self.config.certfile,
                    keyfile=self.config.keyfile)
                conn = ctx.wrap_socket(conn, server_side=True)
                return conn
            except Exception as e:
                logger.exception('Error encountered', exc_info=e)
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    logger.exception('Error trying to shutdown client socket', exc_info=e)
                finally:
                    conn.close()
                return None
        return conn

    def send_server_error(self, e: Exception) -> None:
        logger.exception('Server error', exc_info=e)
        self.client.queue(build_http_response(
            500, b'Server Error'
        ))
        self.client.flush()

    def connection_inactive_for(self) -> int:
        return (self.now() - self.last_activity).seconds

    def is_connection_inactive(self) -> bool:
        # TODO: Add input argument option for timeout
        return self.connection_inactive_for() > 30

    def handle_writables(self, writables: List[Union[int, _HasFileno]]) -> bool:
        if self.client.buffer_size() > 0 and self.client.connection in writables:
            logger.debug('Client is write, flushing buffer')
            try:
                # Invoke plugin.on_response_chunk
                chunk = self.client.buffer
                for plugin in self.plugins.values():
                    chunk = plugin.on_response_chunk(chunk)
                    if chunk is None:
                        break

                self.client.flush()
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for client')
                return True
        return False

    def handle_readables(self, readables: List[Union[int, _HasFileno]]) -> bool:
        if self.client.connection in readables:
            logger.debug('Client is ready for reads, reading')
            client_data = self.client.recv(self.config.client_recvbuf_size)
            self.last_activity = self.now()
            if not client_data:
                logger.debug('Client closed connection, tearing down...')
                self.client.closed = True
                return True

            # ProtocolHandlerPlugin.on_client_data
            plugin_index = 0
            plugins = list(self.plugins.values())
            while plugin_index < len(plugins) and client_data:
                client_data = plugins[plugin_index].on_client_data(client_data)
                if client_data is None:
                    break
                plugin_index += 1

            if client_data:
                try:
                    # Parse http request
                    self.request.parse(client_data)
                    if self.request.state == httpParserStates.COMPLETE:
                        # Invoke plugin.on_request_complete
                        for plugin in self.plugins.values():
                            upgraded_sock = plugin.on_request_complete()
                            if isinstance(upgraded_sock, ssl.SSLSocket):
                                logger.debug(
                                    'Updated client conn to %s', upgraded_sock)
                                self.client._conn = upgraded_sock
                                # Update self.client.conn references for all
                                # plugins
                                for plugin_ in self.plugins.values():
                                    if plugin_ != plugin:
                                        plugin_.client._conn = upgraded_sock
                                        logger.debug(
                                            'Upgraded client conn for plugin %s', str(plugin_))
                            elif isinstance(upgraded_sock, bool) and upgraded_sock:
                                return True
                except ProtocolException as e:
                    logger.exception(
                        'ProtocolException type raised', exc_info=e)
                    response = e.response(self.request)
                    if response:
                        self.client.queue(response)
                        # But is client also ready for writes?
                        self.client.flush()
                    else:
                        self.send_server_error(e)
                    return True
                except Exception as e:
                    self.send_server_error(e)
                    return True
        return False

    def get_events(self) -> Dict[socket.socket, int]:
        events: Dict[socket.socket, int] = {
            self.client.connection: selectors.EVENT_READ
        }
        if self.client.has_buffer():
            events[self.client.connection] |= selectors.EVENT_WRITE

        # ProtocolHandlerPlugin.get_descriptors
        for plugin in self.plugins.values():
            plugin_read_desc, plugin_write_desc = plugin.get_descriptors()
            for r in plugin_read_desc:
                if r not in events:
                    events[r] = selectors.EVENT_READ
                else:
                    events[r] |= selectors.EVENT_READ
            for w in plugin_write_desc:
                if w not in events:
                    events[w] = selectors.EVENT_WRITE
                else:
                    events[w] |= selectors.EVENT_WRITE

        return events

    def handle_events(self, readables: List[Union[int, _HasFileno]], writables: List[Union[int, _HasFileno]]) -> bool:
        """Returns True if proxy must teardown."""
        # Flush buffer for ready to write sockets
        teardown = self.handle_writables(writables)
        if teardown:
            return True

        # Invoke plugin.write_to_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.write_to_descriptors(writables)
            if teardown:
                return True

        # Read from ready to read sockets
        teardown = self.handle_readables(readables)
        if teardown:
            return True

        # Invoke plugin.read_from_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.read_from_descriptors(readables)
            if teardown:
                return True

        # Teardown if client buffer is empty and connection is inactive
        if self.client.buffer_size() == 0:
            if self.is_connection_inactive():
                logger.debug(
                    'Client buffer is empty and maximum inactivity has reached '
                    'between client and server connection, tearing down...')
                return True

        return False

    def run_once(self) -> bool:
        events = self.get_events()
        for fd in events:
            self.selector.register(fd, events[fd])

        # Select
        e: List[Tuple[selectors.SelectorKey, int]] = self.selector.select(timeout=1)
        readables = []
        writables = []
        for key, mask in e:
            if mask & selectors.EVENT_READ:
                readables.append(key.fileobj)
            if mask & selectors.EVENT_WRITE:
                writables.append(key.fileobj)

        teardown = self.handle_events(readables, writables)

        # Unregister
        for fd in events.keys():
            self.selector.unregister(fd)

        if teardown:
            return True

        return False

    def run(self) -> None:
        logger.debug('Proxying connection %r' % self.client.connection)
        try:
            while True:
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:  # pragma: no cover
            pass
        except Exception as e:
            logger.exception(
                'Exception while handling connection %r' %
                self.client.connection, exc_info=e)
        finally:
            # Invoke plugin.on_client_connection_close
            for plugin in self.plugins.values():
                plugin.on_client_connection_close()

            logger.debug(
                'Closing proxy for connection %r '
                'at address %r with pending client buffer size %d bytes' %
                (self.client.connection, self.client.addr, self.client.buffer_size()))

            if not self.client.closed:
                try:
                    self.client.connection.shutdown(socket.SHUT_RDWR)
                    logger.debug('Client connection shutdown successful')
                except OSError:
                    pass
                finally:
                    self.client.close()
                    logger.debug('Client connection closed')


class DevtoolsEventGeneratorPlugin(ProtocolHandlerPlugin):
    """
    DevtoolsEventGeneratorPlugin taps into core `ProtocolHandler`
    plugin to generate events necessary for integration with
    devtools frontend.

    A DevtoolsEventGeneratorPlugin instance is created per request.
    Per request devtool events are queued into a multiprocessing queue.
    """

    frame_id = secrets.token_hex(8)
    loader_id = secrets.token_hex(8)

    def __init__(
            self,
            config: ProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        self.id: str = f'{ os.getpid() }-{ threading.get_ident() }-{ time.time() }'
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        super().__init__(config, client, request)

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []

    def write_to_descriptors(self, w: List[Union[int, _HasFileno]]) -> bool:
        return False

    def read_from_descriptors(self, r: List[Union[int, _HasFileno]]) -> bool:
        return False

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw

    def on_request_complete(self) -> Union[socket.socket, bool]:
        # Handle devtool frontend websocket upgrade
        if self.config.devtools_event_queue:
            self.config.devtools_event_queue.put({
                'method': 'Network.requestWillBeSent',
                'params': self.request_will_be_sent(),
            })
        return False

    def on_response_chunk(self, chunk: bytes) -> bytes:
        if self.config.devtools_event_queue:
            self.response.parse(chunk)
            if self.response.state >= httpParserStates.HEADERS_COMPLETE:
                self.config.devtools_event_queue.put({
                    'method': 'Network.responseReceived',
                    'params': self.response_received(),
                })
            if self.response.state >= httpParserStates.RCVING_BODY:
                self.config.devtools_event_queue.put({
                    'method': 'Network.dataReceived',
                    'params': self.data_received(chunk)
                })
            if self.response.state == httpParserStates.COMPLETE:
                self.config.devtools_event_queue.put({
                    'method': 'Network.loadingFinished',
                    'params': self.loading_finished()
                })
        return chunk

    def on_client_connection_close(self) -> None:
        pass

    def request_will_be_sent(self) -> Dict[str, Any]:
        now = time.time()
        return {
            'requestId': self.id,
            'frameId': self.frame_id,
            'loaderId': self.loader_id,
            'documentURL': 'http://proxy-py/devtools',
            'request': {
                'url': text_(
                    self.request.build_url()
                    if self.request.has_upstream_server() else
                    b'http://proxy-py' + self.request.build_url()
                ),
                'method': text_(self.request.method),
                'headers': {text_(v[0]): text_(v[1]) for v in self.request.headers.values()},
                'initialPriority': 'High',
                'mixedContentType': 'none',
                'postData': None if self.request.method != 'POST'
                else text_(self.request.body)
            },
            'timestamp': now - START_TIME,
            'wallTime': now,
            'initiator': {
                'type': 'other'
            },
            'type': text_(self.request.header(b'content-type'))
            if self.request.has_header(b'content-type')
            else 'Other'
        }

    def response_received(self) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'frameId': self.frame_id,
            'loaderId': self.loader_id,
            'timestamp': time.time(),
            'type': text_(self.response.header(b'content-type'))
            if self.response.has_header(b'content-type')
            else 'Other',
            'response': {}
        }

    def data_received(self, chunk: bytes) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'timestamp': time.time(),
            'dataLength': len(chunk),
            'encodedDataLength': len(chunk),
        }

    def loading_finished(self) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'timestamp': time.time(),
            'encodedDataLength': self.response.total_size
        }


def is_py3() -> bool:
    """Exists only to avoid mocking sys.version_info in tests."""
    return sys.version_info[0] == 3


def set_open_file_limit(soft_limit: int) -> None:
    """Configure open file description soft limit on supported OS."""
    if os.name != 'nt':  # resource module not available on Windows OS
        curr_soft_limit, curr_hard_limit = resource.getrlimit(
            resource.RLIMIT_NOFILE)
        if curr_soft_limit < soft_limit < curr_hard_limit:
            resource.setrlimit(
                resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
            logger.debug(
                'Open file descriptor soft limit set to %d' %
                soft_limit)


def load_plugins(plugins: bytes) -> Dict[bytes, List[type]]:
    """Accepts a comma separated list of Python modules and returns
    a list of respective Python classes."""
    p: Dict[bytes, List[type]] = {
        b'ProtocolHandlerPlugin': [],
        b'HttpProxyBasePlugin': [],
        b'HttpWebServerBasePlugin': [],
    }
    for plugin in plugins.split(COMMA):
        plugin = plugin.strip()
        if plugin == b'':
            continue
        module_name, klass_name = plugin.rsplit(DOT, 1)
        if module_name == 'proxy':
            klass = getattr(__name__, text_(klass_name))
        else:
            klass = getattr(
                importlib.import_module(
                    text_(module_name)),
                text_(klass_name))
        base_klass = inspect.getmro(klass)[1]
        p[bytes_(base_klass.__name__)].append(klass)
        logger.info(
            'Loaded %s %s.%s',
            'plugin' if klass.__name__ != 'HttpWebServerRouteHandler' else 'route',
            text_(module_name),
            # HttpWebServerRouteHandler route decorator adds a special
            # staticmethod to return decorated function name
            klass.__name__ if klass.__name__ != 'HttpWebServerRouteHandler' else klass.name())
    return p


def setup_logger(
        log_file: Optional[str] = DEFAULT_LOG_FILE,
        log_level: str = DEFAULT_LOG_LEVEL,
        log_format: str = DEFAULT_LOG_FORMAT) -> None:
    ll = getattr(
        logging,
        {'D': 'DEBUG',
         'I': 'INFO',
         'W': 'WARNING',
         'E': 'ERROR',
         'C': 'CRITICAL'}[log_level.upper()[0]])
    if log_file:
        logging.basicConfig(
            filename=log_file,
            filemode='a',
            level=ll,
            format=log_format)
    else:
        logging.basicConfig(level=ll, format=log_format)


def init_parser() -> argparse.ArgumentParser:
    """Initializes and returns argument parser."""
    parser = argparse.ArgumentParser(
        description='proxy.py v%s' % __version__,
        epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
    )
    # Argument names are ordered alphabetically.
    parser.add_argument(
        '--backlog',
        type=int,
        default=DEFAULT_BACKLOG,
        help='Default: 100. Maximum number of pending connections to proxy server')
    parser.add_argument(
        '--basic-auth',
        type=str,
        default=DEFAULT_BASIC_AUTH,
        help='Default: No authentication. Specify colon separated user:password '
             'to enable basic authentication.')
    parser.add_argument(
        '--ca-key-file',
        type=str,
        default=DEFAULT_CA_KEY_FILE,
        help='Default: None. CA key to use for signing dynamically generated '
             'HTTPS certificates.  If used, must also pass --ca-cert-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-cert-dir',
        type=str,
        default=DEFAULT_CA_CERT_DIR,
        help='Default: ~/.proxy.py. Directory to store dynamically generated certificates. '
             'Also see --ca-key-file, --ca-cert-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-cert-file',
        type=str,
        default=DEFAULT_CA_CERT_FILE,
        help='Default: None. Signing certificate to use for signing dynamically generated '
             'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-signing-key-file',
        type=str,
        default=DEFAULT_CA_SIGNING_KEY_FILE,
        help='Default: None. CA signing key to use for dynamic generation of '
             'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-cert-file'
    )
    parser.add_argument(
        '--cert-file',
        type=str,
        default=DEFAULT_CERT_FILE,
        help='Default: None. Server certificate to enable end-to-end TLS encryption with clients. '
             'If used, must also pass --key-file.'
    )
    parser.add_argument(
        '--client-recvbuf-size',
        type=int,
        default=DEFAULT_CLIENT_RECVBUF_SIZE,
        help='Default: 1 MB. Maximum amount of data received from the '
             'client in a single recv() operation. Bump this '
             'value for faster uploads at the expense of '
             'increased RAM.')
    parser.add_argument(
        '--disable-headers',
        type=str,
        default=COMMA.join(DEFAULT_DISABLE_HEADERS),
        help='Default: None.  Comma separated list of headers to remove before '
             'dispatching client request to upstream server.')
    parser.add_argument(
        '--disable-http-proxy',
        action='store_true',
        default=DEFAULT_DISABLE_HTTP_PROXY,
        help='Default: False.  Whether to disable proxy.HttpProxyPlugin.')
    parser.add_argument(
        '--enable-devtools',
        action='store_true',
        default=DEFAULT_ENABLE_DEVTOOLS,
        help='Default: False.  Enables integration with Chrome Devtool Frontend.'
    )
    parser.add_argument(
        '--enable-static-server',
        action='store_true',
        default=DEFAULT_ENABLE_STATIC_SERVER,
        help='Default: False.  Enable inbuilt static file server. '
             'Optionally, also use --static-server-dir to serve static content '
             'from custom directory.  By default, static file server serves '
             'from public folder.'
    )
    parser.add_argument(
        '--enable-web-server',
        action='store_true',
        default=DEFAULT_ENABLE_WEB_SERVER,
        help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.')
    parser.add_argument('--hostname',
                        type=str,
                        default=str(DEFAULT_IPV6_HOSTNAME),
                        help='Default: ::1. Server IP address.')
    parser.add_argument(
        '--key-file',
        type=str,
        default=DEFAULT_KEY_FILE,
        help='Default: None. Server key file to enable end-to-end TLS encryption with clients. '
             'If used, must also pass --cert-file.'
    )
    parser.add_argument(
        '--log-level',
        type=str,
        default=DEFAULT_LOG_LEVEL,
        help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
             'Both upper and lowercase values are allowed. '
             'You may also simply use the leading character e.g. --log-level d')
    parser.add_argument('--log-file', type=str, default=DEFAULT_LOG_FILE,
                        help='Default: sys.stdout. Log file destination.')
    parser.add_argument('--log-format', type=str, default=DEFAULT_LOG_FORMAT,
                        help='Log format for Python logger.')
    parser.add_argument('--num-workers', type=int, default=DEFAULT_NUM_WORKERS,
                        help='Defaults to number of CPU cores.')
    parser.add_argument(
        '--open-file-limit',
        type=int,
        default=DEFAULT_OPEN_FILE_LIMIT,
        help='Default: 1024. Maximum number of files (TCP connections) '
             'that proxy.py can open concurrently.')
    parser.add_argument(
        '--pac-file',
        type=str,
        default=DEFAULT_PAC_FILE,
        help='A file (Proxy Auto Configuration) or string to serve when '
             'the server receives a direct file request. '
             'Using this option enables proxy.HttpWebServerPlugin.')
    parser.add_argument(
        '--pac-file-url-path',
        type=str,
        default=text_(DEFAULT_PAC_FILE_URL_PATH),
        help='Default: %s. Web server path to serve the PAC file.' %
             text_(DEFAULT_PAC_FILE_URL_PATH))
    parser.add_argument(
        '--pid-file',
        type=str,
        default=DEFAULT_PID_FILE,
        help='Default: None. Save parent process ID to a file.')
    parser.add_argument(
        '--plugins',
        type=str,
        default=DEFAULT_PLUGINS,
        help='Comma separated plugins')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help='Default: 8899. Server port.')
    parser.add_argument(
        '--server-recvbuf-size',
        type=int,
        default=DEFAULT_SERVER_RECVBUF_SIZE,
        help='Default: 1 MB. Maximum amount of data received from the '
             'server in a single recv() operation. Bump this '
             'value for faster downloads at the expense of '
             'increased RAM.')
    parser.add_argument(
        '--static-server-dir',
        type=str,
        default=DEFAULT_STATIC_SERVER_DIR,
        help='Default: ' + DEFAULT_STATIC_SERVER_DIR + '.  Static server root directory. '
             'This option is only applicable when static server is also enabled. '
             'See --enable-static-server.'
    )
    parser.add_argument(
        '--version',
        '-v',
        action='store_true',
        default=DEFAULT_VERSION,
        help='Prints proxy.py version.')
    return parser


def main(input_args: List[str]) -> None:
    if not is_py3() and not UNDER_TEST:
        print(
            'DEPRECATION: "develop" branch no longer supports Python 2.7.  Kindly upgrade to Python 3+. '
            'If for some reasons you cannot upgrade, consider using "master" branch or simply '
            '"pip install proxy.py".'
            '\n\n'
            'DEPRECATION: Python 2.7 will reach the end of its life on January 1st, 2020. '
            'Please upgrade your Python as Python 2.7 won\'t be maintained after that date. '
            'A future version of pip will drop support for Python 2.7.')
        sys.exit(0)

    args = init_parser().parse_args(input_args)

    if args.version:
        print(text_(version))
        sys.exit(0)

    if (args.cert_file and args.key_file) and \
            (args.ca_key_file and args.ca_cert_file and args.ca_signing_key_file):
        print('HTTPS interception not supported when proxy.py is serving over HTTPS')
        sys.exit(0)

    try:
        setup_logger(args.log_file, args.log_level, args.log_format)
        set_open_file_limit(args.open_file_limit)

        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        default_plugins = ''
        if not args.disable_http_proxy:
            default_plugins += 'proxy.HttpProxyPlugin,'
        if args.enable_devtools:
            default_plugins += 'proxy.HttpWebServerPlugin,proxy.DevtoolsEventGeneratorPlugin,'
        if args.enable_web_server or \
                args.pac_file is not None or \
                args.enable_static_server:
            default_plugins += 'proxy.HttpWebServerPlugin,'
        if args.enable_devtools:
            default_plugins += 'proxy.DevtoolsFrontendPlugin,'
        if args.pac_file is not None:
            default_plugins += 'proxy.HttpWebServerPacFilePlugin,'

        config = ProtocolConfig(
            auth_code=auth_code,
            server_recvbuf_size=args.server_recvbuf_size,
            client_recvbuf_size=args.client_recvbuf_size,
            pac_file=bytes_(args.pac_file),
            pac_file_url_path=bytes_(args.pac_file_url_path),
            disable_headers=[
                header.lower() for header in bytes_(
                    args.disable_headers).split(COMMA) if header.strip() != b''],
            certfile=args.cert_file,
            keyfile=args.key_file,
            ca_cert_dir=args.ca_cert_dir,
            ca_key_file=args.ca_key_file,
            ca_cert_file=args.ca_cert_file,
            ca_signing_key_file=args.ca_signing_key_file,
            hostname=ipaddress.ip_address(args.hostname),
            port=args.port,
            backlog=args.backlog,
            num_workers=args.num_workers if args.num_workers > 0 else multiprocessing.cpu_count(),
            static_server_dir=args.static_server_dir,
            enable_static_server=args.enable_static_server,
            devtools_event_queue=multiprocessing.Manager().Queue())

        config.plugins = load_plugins(
            bytes_(
                '%s%s' %
                (default_plugins, args.plugins)))

        acceptor_pool = AcceptorPool(
            hostname=config.hostname,
            port=config.port,
            backlog=config.backlog,
            num_workers=config.num_workers,
            work_klass=ProtocolHandler,
            config=config)
        if args.pid_file:
            with open(args.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(os.getpid()))
        acceptor_pool.setup()

        try:
            # TODO: Introduce cron feature instead of mindless sleep
            while True:
                time.sleep(1)
        except Exception as e:
            logger.exception('exception', exc_info=e)
        finally:
            acceptor_pool.shutdown()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        if args.pid_file:
            if os.path.exists(args.pid_file):
                os.remove(args.pid_file)


if __name__ == '__main__':
    main(sys.argv[1:])  # pragma: no cover
