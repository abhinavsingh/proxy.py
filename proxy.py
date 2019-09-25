#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    Lightweight Programmable HTTP, HTTPS, WebSockets Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import base64
import datetime
import errno
import importlib
import inspect
import ipaddress
import logging
import multiprocessing
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from multiprocessing import connection
from multiprocessing.reduction import send_handle, recv_handle
from typing import Any, Dict, List, Tuple, Optional, Union, NamedTuple
from urllib import parse as urlparse

import select

if os.name != 'nt':
    import resource

VERSION = (1, 0, 0)
__version__ = '.'.join(map(str, VERSION[0:3]))
__description__ = 'Lightweight Programmable HTTP, HTTPS, WebSockets Proxy Server in a single Python file'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_BUFFER_SIZE = 1024 * 1024
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_DISABLE_HEADERS: List[bytes] = []
DEFAULT_IPV4_HOSTNAME = ipaddress.IPv4Address('127.0.0.1')
DEFAULT_IPV6_HOSTNAME = ipaddress.IPv6Address('::1')
DEFAULT_PORT = 8899
DEFAULT_DISABLE_HTTP_PROXY = False
DEFAULT_ENABLE_WEB_SERVER = False
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_PAC_FILE_URL_PATH = b'/'
DEFAULT_PID_FILE = None
DEFAULT_NUM_WORKERS = 0
DEFAULT_PLUGINS = ''
DEFAULT_VERSION = False
DEFAULT_LOG_FORMAT = '%(asctime)s - %(levelname)s - pid:%(process)d - %(funcName)s:%(lineno)d - %(message)s'
DEFAULT_LOG_FILE = None

# Set to True if under test
UNDER_TEST = False


def text_(s: Any, encoding: str = 'utf-8', errors: str = 'strict') -> Any:
    """Utility to ensure text-like usability.

    If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, bytes):
        return s.decode(encoding, errors)
    return s


def bytes_(s: Any, encoding: str = 'utf-8', errors: str = 'strict') -> Any:
    """Utility to ensure binary-like usability.

    If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s


version = bytes_(__version__)
CRLF, COLON, WHITESPACE, COMMA, DOT = b'\r\n', b':', b' ', b',', b'.'
PROXY_AGENT_HEADER = b'Proxy-agent: proxy.py v' + version

##
# Various NamedTuples
#
# collections.namedtuple were replaced with typing.NamedTuple
# for mypy compliance. Unfortunately, we can't seem to use
# a NamedTuple as a type.
##

TcpConnectionTypes = NamedTuple('TcpConnectionTypes', [
    ('SERVER', int),
    ('CLIENT', int),
])
tcpConnectionTypes = TcpConnectionTypes(1, 2)

WorkerOperations = NamedTuple('WorkerOperations', [
    ('HTTP_PROTOCOL', int),
    ('SHUTDOWN', int),
])
workerOperations = WorkerOperations(1, 2)

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


class TcpConnection:
    """TCP server/client connection abstraction."""

    def __init__(self, tag: int):
        self.conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None
        self.buffer: bytes = b''
        self.closed: bool = False
        self.tag: str = 'server' if tag == tcpConnectionTypes.SERVER else 'client'

    def send(self, data: bytes) -> int:
        """Users must handle BrokenPipeError exceptions"""
        if not self.conn:
            raise KeyError('conn is None')
        return self.conn.send(data)

    def recv(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> Optional[bytes]:
        if not self.conn:
            raise KeyError('conn is None')
        try:
            data: bytes = self.conn.recv(buffer_size)
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
                    (self.tag, self.conn, e))
        return None

    def close(self) -> bool:
        if not self.conn:
            raise KeyError('conn is None')
        if not self.closed:
            self.conn.close()
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
        sent: int = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        logger.debug('flushed %d bytes to %s' % (sent, self.tag))
        return sent


class TcpServerConnection(TcpConnection):
    """Establishes connection to destination server."""

    def __init__(self, host: str, port: int):
        super().__init__(tcpConnectionTypes.SERVER)
        self.addr: Tuple[str, int] = (host, int(port))

    def __del__(self) -> None:
        if self.conn:
            self.close()

    def connect(self) -> None:
        try:
            ip = ipaddress.ip_address(text_(self.addr[0]))
            if ip.version == 4:
                self.conn = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM, 0)
                self.conn.connect((self.addr[0], self.addr[1]))
            else:
                self.conn = socket.socket(
                    socket.AF_INET6, socket.SOCK_STREAM, 0)
                self.conn.connect((self.addr[0], self.addr[1], 0, 0))
        except ValueError:
            # Not a valid IP address, most likely its a domain name,
            # try to establish dual stack IPv4/IPv6 connection.
            self.conn = socket.create_connection((self.addr[0], self.addr[1]))


class TcpClientConnection(TcpConnection):
    """Accepted client connection."""

    def __init__(self, conn: Union[ssl.SSLSocket,
                                   socket.socket], addr: Tuple[str, int]):
        super().__init__(tcpConnectionTypes.CLIENT)
        self.conn: Union[ssl.SSLSocket, socket.socket] = conn
        self.addr: Tuple[str, int] = addr


class TcpServer(ABC):
    """TcpServer server implementation.

    Inheritor MUST implement `handle` method. It accepts an instance of `TcpClientConnection`.
    Optionally, can also implement `setup` and `shutdown` methods for custom bootstrapping and tearing
    down internal state.
    """

    def __init__(self,
                 hostname: Union[ipaddress.IPv4Address,
                                 ipaddress.IPv6Address] = DEFAULT_IPV6_HOSTNAME,
                 port: int = DEFAULT_PORT,
                 backlog: int = DEFAULT_BACKLOG,
                 family: socket.AddressFamily = socket.AF_INET6):
        self.port: int = port
        self.backlog: int = backlog
        self.socket: Optional[socket.socket] = None
        self.running: bool = False
        self.family: socket.AddressFamily = family
        self.hostname: Union[ipaddress.IPv4Address,
                             ipaddress.IPv6Address] = hostname

    @abstractmethod
    def setup(self) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def handle(self, client: TcpClientConnection) -> None:
        raise NotImplementedError()  # pragma: no cover

    @abstractmethod
    def shutdown(self) -> None:
        pass  # pragma: no cover

    def stop(self) -> None:
        self.running = False

    def run(self) -> None:
        self.running = True
        self.setup()
        try:
            self.socket = socket.socket(self.family, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((str(self.hostname), self.port))
            self.socket.listen(self.backlog)
            logger.info('Started server on %s:%d' % (self.hostname, self.port))
            while self.running:
                r, w, x = select.select([self.socket], [], [], 1)
                if self.socket in r:
                    try:
                        conn, addr = self.socket.accept()
                        client = TcpClientConnection(conn, addr)
                        self.handle(client)
                    except ssl.SSLError as e:
                        logger.exception('SSLError encountered', exc_info=e)

        except Exception as e:
            logger.exception('Exception while running the server %r' % e)
        finally:
            self.shutdown()
            logger.info('Closing server socket')
            if self.socket:
                self.socket.close()


class HttpProtocolConfig:
    """Holds various configuration values applicable to HttpProtocolHandler.

    This config class helps us avoid passing around bunch of key/value pairs across methods.
    """

    ROOT_DATA_DIR_NAME = '.proxy.py'
    GENERATED_CERTS_DIR_NAME = 'certificates'

    def __init__(
            self,
            auth_code: Optional[bytes] = DEFAULT_BASIC_AUTH,
            server_recvbuf_size: int = DEFAULT_SERVER_RECVBUF_SIZE,
            client_recvbuf_size: int = DEFAULT_CLIENT_RECVBUF_SIZE,
            pac_file: Optional[bytes] = DEFAULT_PAC_FILE,
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
            backlog: int = DEFAULT_BACKLOG) -> None:
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
        self.family: socket.AddressFamily = socket.AF_INET if hostname.version == 4 else socket.AF_INET6

        self.proxy_py_data_dir = os.path.join(
            str(pathlib.Path.home()), self.ROOT_DATA_DIR_NAME)
        os.makedirs(self.proxy_py_data_dir, exist_ok=True)

        self.ca_cert_dir: Optional[str] = ca_cert_dir
        if self.ca_cert_dir is None:
            self.ca_cert_dir = os.path.join(
                self.proxy_py_data_dir, self.GENERATED_CERTS_DIR_NAME)
            os.makedirs(self.ca_cert_dir, exist_ok=True)


class MultiCoreRequestDispatcher(TcpServer):
    """MultiCoreRequestDispatcher.

    Pre-spawns worker process to utilize all cores available on the system.  Accepted `TcpClientConnection` is
    dispatched over a queue to workers.  One of the worker picks up the work and starts a new thread to handle the
    client request.
    """

    def __init__(self, config: HttpProtocolConfig) -> None:
        super().__init__(
            hostname=config.hostname,
            port=config.port,
            backlog=config.backlog,
            family=config.family)
        self.workers: List[Worker] = []
        self.work_queues: List[Tuple[connection.Connection,
                                     connection.Connection]] = []
        self.current_worker_id = 0
        self.config: HttpProtocolConfig = config

    def setup(self) -> None:
        for worker_id in range(self.config.num_workers):
            work_queue = multiprocessing.Pipe()

            worker = Worker(work_queue[1], self.config)
            worker.daemon = True
            worker.start()

            self.workers.append(worker)
            self.work_queues.append(work_queue)
        logger.info('Started %d workers' % self.config.num_workers)

    def handle(self, client: TcpClientConnection) -> None:
        # Dispatch in round robin fashion
        work_queue = self.work_queues[self.current_worker_id]
        logger.debug(
            'Dispatched client request to worker id %d',
            self.current_worker_id)
        # Dispatch non-socket data first, followed by fileno using reduction
        work_queue[0].send((workerOperations.HTTP_PROTOCOL, client.addr))
        send_handle(work_queue[0], client.conn.fileno(),
                    self.workers[self.current_worker_id].pid)
        # Close parent handler
        client.close()
        self.current_worker_id += 1
        self.current_worker_id %= self.config.num_workers

    def shutdown(self) -> None:
        logger.info('Shutting down %d workers' % self.config.num_workers)
        for work_queue in self.work_queues:
            work_queue[0].send((workerOperations.SHUTDOWN, None))
            work_queue[0].close()
        for worker in self.workers:
            worker.join()


class Worker(multiprocessing.Process):
    """Generic worker class implementation.

    Worker instance accepts (operation, payload) over work queue and
    depending upon requested operation starts a new thread to handle the work.
    """

    def __init__(
            self,
            work_queue: connection.Connection,
            config: HttpProtocolConfig):
        super().__init__()
        self.work_queue: connection.Connection = work_queue
        self.config: HttpProtocolConfig = config

    def run(self) -> None:
        while True:
            try:
                op, payload = self.work_queue.recv()
                if op == workerOperations.HTTP_PROTOCOL:
                    fileno = recv_handle(self.work_queue)
                    conn = socket.fromfd(
                        fileno, family=self.config.family, type=socket.SOCK_STREAM)
                    # TODO(abhinavsingh): Move handshake logic within
                    # HttpProtocolHandler.
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
                        except OSError as e:
                            logger.exception(
                                'OSError encountered while ssl wrapping the client socket', exc_info=e)
                            conn.close()
                            continue
                    proxy = HttpProtocolHandler(
                        TcpClientConnection(conn=conn, addr=payload),
                        config=self.config)
                    proxy.setDaemon(True)
                    proxy.start()
                elif op == workerOperations.SHUTDOWN:
                    logger.debug('Worker shutting down....')
                    self.work_queue.close()
                    break
            except ConnectionRefusedError:
                pass
            except KeyboardInterrupt:  # pragma: no cover
                break


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
            line, raw = HttpParser.find_line(raw)
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

        # Can simply be b'', then set type as bytes?
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
        line, raw = HttpParser.find_line(raw)
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
            self.reason = b' '.join(line[2:])
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
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS

        assert self.method and self.version
        req = b' '.join([self.method, self.build_url(), self.version])
        req += CRLF

        for k in self.headers:
            if k.lower() not in disable_headers:
                req += self.build_header(self.headers[k]
                                         [0], self.headers[k][1]) + CRLF

        req += CRLF
        if self.body:
            req += self.body

        return req

    @staticmethod
    def build_header(k: bytes, v: bytes) -> bytes:
        return k + b': ' + v

    @staticmethod
    def find_line(raw: bytes) -> Tuple[Optional[bytes], bytes]:
        """Finds first line of request ending in CRLF.

        If no CRLF is found, line is None.
        Also returns pending buffer after received line of request."""
        pos = raw.find(CRLF)
        if pos == -1:
            return None, raw
        line = raw[:pos]
        rest = raw[pos + len(CRLF):]
        return line, rest

    ##########################################################################
    # HttpParser was originally written to parse the incoming raw Http requests.
    # Since request / response objects passed to HttpProtocolBasePlugin methods
    # are also HttpParser objects, methods below were added to simplify developer API.
    ##########################################################################

    def has_upstream_server(self) -> bool:
        """Host field SHOULD be None for incoming local WebServer requests."""
        return True if self.host is not None else False

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


class HttpProtocolException(Exception):
    """Top level HttpProtocolException exception class.

    All exceptions raised during execution of Http request lifecycle MUST
    inherit HttpProtocolException base class. Implement response() method
    to optionally return custom response to client."""

    def response(self, request: HttpParser) -> Optional[bytes]:
        pass  # pragma: no cover


class HttpRequestRejected(HttpProtocolException):
    """Generic exception that can be used to reject the client requests.

    Connections can either be dropped/closed or optionally an
    HTTP status code can be returned."""

    def __init__(self,
                 status_code: Optional[int] = None,
                 reason: Optional[bytes] = None,
                 body: Optional[bytes] = None):
        super().__init__()
        self.status_code: Optional[int] = status_code
        self.reason: Optional[bytes] = reason
        self.body: Optional[bytes] = body

    def response(self, _request: HttpParser) -> Optional[bytes]:
        pkt = []
        if self.status_code is not None:
            line = b'HTTP/1.1 ' + bytes_(str(self.status_code))
            if self.reason:
                line += b' ' + self.reason
            pkt.append(line)
            pkt.append(PROXY_AGENT_HEADER)
        if self.body:
            pkt.append(b'Content-Length: ' + bytes_(str(len(self.body))))
            pkt.append(CRLF)
            pkt.append(self.body)
        else:
            if len(pkt) > 0:
                pkt.append(CRLF)
        return CRLF.join(pkt) if len(pkt) > 0 else None


class HttpProtocolBasePlugin(ABC):
    """Base HttpProtocolHandler Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            config: HttpProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        self.config: HttpProtocolConfig = config
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
            self) -> Tuple[List[socket.socket], List[socket.socket], List[socket.socket]]:
        return [], [], []  # pragma: no cover

    @abstractmethod
    def flush_to_descriptors(self, w: List[socket.socket]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def read_from_descriptors(self, r: List[socket.socket]) -> bool:
        pass  # pragma: no cover

    @abstractmethod
    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw  # pragma: no cover

    @abstractmethod
    def on_request_complete(self) -> Union[socket.socket, bool]:
        """Called right after client request parser has reached COMPLETE state."""
        pass  # pragma: no cover

    @abstractmethod
    def handle_response_chunk(self, chunk: bytes) -> bytes:
        """Handle data chunks as received from the server.

        Return optionally modified chunk to return back to client."""
        return chunk  # pragma: no cover

    @abstractmethod
    def access_log(self) -> None:
        pass  # pragma: no cover

    @abstractmethod
    def on_client_connection_close(self) -> None:
        pass  # pragma: no cover


class ProxyConnectionFailed(HttpProtocolException):
    """Exception raised when HttpProxyPlugin is unable to establish connection to upstream server."""

    RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 502 Bad Gateway',
        PROXY_AGENT_HEADER,
        b'Content-Length: 11',
        b'Connection: close',
        CRLF
    ]) + b'Bad Gateway'

    def __init__(self, host: str, port: int, reason: str):
        self.host: str = host
        self.port: int = port
        self.reason: str = reason

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT

    def __str__(self) -> str:
        return '<ProxyConnectionFailed - %s:%s - %s>' % (
            self.host, self.port, self.reason)


class ProxyAuthenticationFailed(HttpProtocolException):
    """Exception raised when Http Proxy auth is enabled and
    incoming request doesn't present necessary credentials."""

    RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 407 Proxy Authentication Required',
        PROXY_AGENT_HEADER,
        b'Content-Length: 29',
        b'Connection: close',
        b'Proxy-Authenticate: Basic',
        CRLF
    ]) + b'Proxy Authentication Required'

    def response(self, _request: HttpParser) -> bytes:
        return self.RESPONSE_PKT


class HttpProxyBasePlugin(ABC):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            config: HttpProtocolConfig,
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
    def before_upstream_connection(self) -> None:
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


class HttpProxyPlugin(HttpProtocolBasePlugin):
    """HttpProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 200 Connection established',
        CRLF
    ])

    # Used to synchronize with other HttpProxyPlugin instances while
    # generating certificates
    lock = threading.Lock()

    def __init__(
            self,
            config: HttpProtocolConfig,
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
            self) -> Tuple[List[socket.socket], List[socket.socket], List[socket.socket]]:
        if not self.request.has_upstream_server():
            return [], [], []

        r: List[socket.socket] = []
        w: List[socket.socket] = []
        if self.server and not self.server.closed and self.server.conn:
            r.append(self.server.conn)
        if self.server and not self.server.closed and self.server.has_buffer() and self.server.conn:
            w.append(self.server.conn)
        return r, w, []

    def flush_to_descriptors(self, w: List[socket.socket]) -> bool:
        if self.request.has_upstream_server() and \
                self.server and not self.server.closed and self.server.conn in w:
            logger.debug('Server is ready for writes, flushing server buffer')
            try:
                self.server.flush()
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for server')
                return True
        return False

    def read_from_descriptors(self, r: List[socket.socket]) -> bool:
        if self.request.has_upstream_server(
        ) and self.server and not self.server.closed and self.server.conn in r:
            logger.debug('Server is ready for reads, reading')
            raw = self.server.recv(self.config.server_recvbuf_size)
            # self.last_activity = HttpProtocolHandler.now()
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
        if self.request.has_upstream_server() and self.server:
            logger.debug(
                'Closed server connection with pending server buffer size %d bytes' %
                self.server.buffer_size())
            if not self.server.closed:
                # Invoke plugin.on_upstream_connection_close
                for plugin in self.plugins.values():
                    plugin.on_upstream_connection_close()
                self.server.close()

    def handle_response_chunk(self, chunk: bytes) -> bytes:
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
                    # Currently we only set CN=example.org on the generated
                    # certificates.
                    gen_cert = subprocess.Popen(
                        ['/usr/bin/openssl', 'req', '-new', '-key', self.config.ca_signing_key_file, '-subj',
                         '/CN=%s' % text_(self.request.host)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
                    sign_cert = subprocess.Popen(
                        ['/usr/bin/openssl', 'x509', '-req', '-days', '365', '-CA', self.config.ca_cert_file, '-CAkey',
                         self.config.ca_key_file, '-set_serial', str(int(time.time() * 1000)), '-out', cert_file_path],
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
            plugin.before_upstream_connection()

        self.authenticate()
        self.connect_upstream()

        for plugin in self.plugins.values():
            plugin.on_upstream_connection()

        # for http connect methods (https requests)
        # queue appropriate response for client
        # notifying about established connection
        if self.request.method == b'CONNECT':
            self.client.queue(
                HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
            # If interception is enabled, generate server certificates
            if self.config.ca_key_file and self.config.ca_cert_file and self.config.ca_signing_key_file:
                # Flush client buffer before wrapping, but is client ready for
                # writes?
                self.client.flush()
                generated_cert = self.generate_upstream_certificate()
                if generated_cert:
                    # If client is communicating over https,
                    # self.client.conn has already been wrapped before.
                    # We could unwrap, but then we can't maintain our https
                    # connection to the client. Below we handle the scenario
                    # when client is communicating to proxy.py using http.
                    if not (self.config.keyfile and self.config.certfile) and \
                            self.server and isinstance(self.server.conn, socket.socket):
                        self.client.conn = ssl.wrap_socket(self.client.conn,
                                                           server_side=True,
                                                           keyfile=self.config.ca_signing_key_file,
                                                           certfile=generated_cert)
                        # Wrap our connection to upstream server connection
                        ctx = ssl.create_default_context(
                            ssl.Purpose.SERVER_AUTH)
                        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
                        self.server.conn = ctx.wrap_socket(
                            self.server.conn, server_hostname=text_(
                                self.request.host))
                        logger.info(
                            'Intercepting traffic using %s', generated_cert)
                        return self.client.conn
        # for general http requests, re-build request packet
        # and queue for the server with appropriate headers
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

    def access_log(self) -> None:
        if not self.request.has_upstream_server():
            return

        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s - %s bytes' %
                (self.client.addr[0],
                 self.client.addr[1],
                 text_(
                     self.request.method),
                 text_(host),
                 text_(port),
                 self.response.total_size))
        elif self.request.method:
            logger.info(
                '%s:%s - %s %s:%s%s - %s %s - %s bytes' %
                (self.client.addr[0], self.client.addr[1], text_(
                    self.request.method), text_(host), port, text_(
                    self.request.build_url()), text_(
                    self.response.code), text_(
                    self.response.reason), self.response.total_size))

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
            raise HttpProtocolException()


class HttpWebServerPlugin(HttpProtocolBasePlugin):
    """HttpProtocolHandler plugin which handles incoming requests to local webserver."""

    DEFAULT_404_RESPONSE = CRLF.join([
        b'HTTP/1.1 404 NOT FOUND',
        b'Server: proxy.py v%s' % version,
        b'Connection: Close',
        CRLF
    ])

    PAC_FILE_RESPONSE_PREFIX = CRLF.join([
        b'HTTP/1.1 200 OK',
        b'Content-Type: application/x-ns-proxy-autoconfig',
        b'Connection: close',
        CRLF
    ])

    def __init__(
            self,
            config: HttpProtocolConfig,
            client: TcpClientConnection,
            request: HttpParser):
        super().__init__(config, client, request)
        if self.config.pac_file:
            try:
                with open(self.config.pac_file, 'rb') as f:
                    logger.debug('Will serve pac file from disk')
                    self.pac_file_content = f.read()
            except IOError:
                logger.debug('Will serve pac file content from buffer')
                self.pac_file_content = self.config.pac_file

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if self.request.has_upstream_server():
            return False

        if self.config.pac_file and self.request.url and \
                self.request.url.path == self.config.pac_file_url_path:
            self.client.queue(self.PAC_FILE_RESPONSE_PREFIX)
            self.client.queue(self.pac_file_content)
            self.client.flush()
        else:
            # Catch all unhandled web server requests, return 404
            self.client.queue(self.DEFAULT_404_RESPONSE)
            # But is client ready for flush?
            self.client.flush()

        return True

    def access_log(self) -> None:
        if self.request.has_upstream_server():
            return
        logger.info(
            '%s:%s - %s %s' %
            (self.client.addr[0], self.client.addr[1], text_(
                self.request.method), text_(
                self.request.build_url())))

    def flush_to_descriptors(self, w: List[socket.socket]) -> bool:
        pass

    def read_from_descriptors(self, r: List[socket.socket]) -> bool:
        pass

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw

    def handle_response_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_client_connection_close(self) -> None:
        pass

    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket], List[socket.socket]]:
        return [], [], []


class HttpProtocolHandler(threading.Thread):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection object and manages HttpProtocolBasePlugin invocations.
    """

    def __init__(self, client: TcpClientConnection,
                 config: Optional[HttpProtocolConfig] = None):
        super().__init__()
        self.start_time: datetime.datetime = self.now()
        self.last_activity: datetime.datetime = self.start_time

        self.client: TcpClientConnection = client
        self.config: HttpProtocolConfig = config if config else HttpProtocolConfig()
        self.request: HttpParser = HttpParser(httpParserTypes.REQUEST_PARSER)

        self.plugins: Dict[str, HttpProtocolBasePlugin] = {}
        if b'HttpProtocolBasePlugin' in self.config.plugins:
            for klass in self.config.plugins[b'HttpProtocolBasePlugin']:
                instance = klass(self.config, self.client, self.request)
                self.plugins[instance.name()] = instance

    @staticmethod
    def now() -> datetime.datetime:
        return datetime.datetime.utcnow()

    def connection_inactive_for(self) -> int:
        return (self.now() - self.last_activity).seconds

    def is_connection_inactive(self) -> bool:
        # TODO: Add input argument option for timeout
        return self.connection_inactive_for() > 30

    def handle_writables(self, writables: List[socket.socket]) -> bool:
        if self.client.conn in writables:
            logger.debug('Client is ready for writes, flushing client buffer')
            try:
                self.client.flush()
            except BrokenPipeError:
                logger.error(
                    'BrokenPipeError when flushing buffer for client')
                return True
        return False

    def handle_readables(self, readables: List[socket.socket]) -> bool:
        if self.client.conn in readables:
            logger.debug('Client is ready for reads, reading')
            client_data = self.client.recv(self.config.client_recvbuf_size)
            self.last_activity = self.now()
            if not client_data:
                logger.debug('Client closed connection, tearing down...')
                self.client.closed = True
                return True

            # HttpProtocolBasePlugin.on_client_data
            plugin_index = 0
            plugins = list(self.plugins.values())
            while plugin_index < len(plugins) and client_data:
                client_data = plugins[plugin_index].on_client_data(client_data)
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
                                self.client.conn = upgraded_sock
                                # Update self.client.conn references for all
                                # plugins
                                for plugin_ in self.plugins.values():
                                    if plugin_ != plugin:
                                        plugin_.client.conn = upgraded_sock
                                        logger.debug(
                                            'Upgraded client conn for plugin %s', str(plugin_))
                            elif isinstance(upgraded_sock, bool) and upgraded_sock:
                                return True
                except Exception as e:
                    if e.__class__.__name__ in (
                            ProxyAuthenticationFailed.__name__, ProxyConnectionFailed.__name__,
                            HttpRequestRejected.__name__):
                        logger.exception(
                            'HttpProtocolException type raised', exc_info=e)
                        response = e.response(self.request)  # type: ignore
                        if response:
                            self.client.queue(response)
                            # But is client also ready for writes?
                            self.client.flush()
                        return True
                    raise e
        return False

    def run_once(self) -> bool:
        """Returns True if proxy must teardown."""
        # Prepare list of descriptors
        read_desc: List[socket.socket] = [self.client.conn]
        write_desc: List[socket.socket] = []
        err_desc: List[socket.socket] = []
        if self.client.has_buffer():
            write_desc.append(self.client.conn)

        # HttpProtocolBasePlugin.get_descriptors
        for plugin in self.plugins.values():
            plugin_read_desc, plugin_write_desc, plugin_err_desc = plugin.get_descriptors()
            read_desc += plugin_read_desc
            write_desc += plugin_write_desc
            err_desc += plugin_err_desc

        readables, writables, errored = select.select(
            read_desc, write_desc, err_desc, 1)

        # Flush buffer for ready to write sockets
        teardown = self.handle_writables(writables)
        if teardown:
            return True

        # Invoke plugin.flush_to_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.flush_to_descriptors(writables)
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

    def run(self) -> None:
        logger.debug('Proxying connection %r' % self.client.conn)
        try:
            while True:
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:  # pragma: no cover
            pass
        except Exception as e:
            logger.exception(
                'Exception while handling connection %r with reason %r' %
                (self.client.conn, e))
        finally:
            # Invoke plugin.access_log
            for plugin in self.plugins.values():
                plugin.access_log()

            if not self.client.closed:
                try:
                    self.client.conn.shutdown(socket.SHUT_RDWR)
                    self.client.close()
                except OSError as e:
                    logger.warning('OSError: %s', str(e))

            # Invoke plugin.on_client_connection_close
            for plugin in self.plugins.values():
                plugin.on_client_connection_close()

            logger.debug(
                'Closed proxy for connection %r '
                'at address %r with pending client buffer size %d bytes' %
                (self.client.conn, self.client.addr, self.client.buffer_size()))


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
        b'HttpProtocolBasePlugin': [],
        b'HttpProxyBasePlugin': []
    }
    for plugin in plugins.split(COMMA):
        plugin = plugin.strip()
        if plugin == b'':
            continue
        module_name, klass_name = plugin.rsplit(DOT, 1)
        module = importlib.import_module(text_(module_name))
        klass = getattr(module, text_(klass_name))
        base_klass = inspect.getmro(klass)[::-1][2:][0]
        p[bytes_(base_klass.__name__)].append(klass)
        logger.info('Loaded plugin %s', klass)
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
        default=None,
        help='Default: None. CA key to use for signing dynamically generated '
             'HTTPS certificates.  If used, must also pass --ca-cert-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-cert-dir',
        type=str,
        default=None,
        help='Default: ~/.proxy.py. Directory to store dynamically generated certificates. '
             'Also see --ca-key-file, --ca-cert-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-cert-file',
        type=str,
        default=None,
        help='Default: None. Signing certificate to use for signing dynamically generated '
             'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-signing-key-file'
    )
    parser.add_argument(
        '--ca-signing-key-file',
        type=str,
        default=None,
        help='Default: None. CA signing key to use for dynamic generation of '
             'HTTPS certificates.  If used, must also pass --ca-key-file and --ca-cert-file'
    )
    parser.add_argument(
        '--cert-file',
        type=str,
        default=None,
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
        default=None,
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
        default=DEFAULT_PAC_FILE_URL_PATH,
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

        config = HttpProtocolConfig(
            auth_code=auth_code,
            server_recvbuf_size=args.server_recvbuf_size,
            client_recvbuf_size=args.client_recvbuf_size,
            pac_file=args.pac_file,
            pac_file_url_path=args.pac_file_url_path,
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
            num_workers=args.num_workers if args.num_workers > 0 else multiprocessing.cpu_count())
        if config.pac_file is not None:
            args.enable_web_server = True

        default_plugins = ''
        if not args.disable_http_proxy:
            default_plugins += 'proxy.HttpProxyPlugin,'
        if args.enable_web_server:
            default_plugins += 'proxy.HttpWebServerPlugin,'
        config.plugins = load_plugins(
            bytes_(
                '%s%s' %
                (default_plugins, args.plugins)))

        server = MultiCoreRequestDispatcher(config=config)
        if args.pid_file:
            with open(args.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(str(os.getpid())))
        server.run()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        if args.pid_file:
            if os.path.exists(args.pid_file):
                os.remove(args.pid_file)


if __name__ == '__main__':
    main(sys.argv[1:])  # pragma: no cover
