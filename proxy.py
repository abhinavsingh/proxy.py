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
import logging
import multiprocessing
import os
import queue
import socket
import sys
import threading
import ipaddress
from collections import namedtuple
from typing import Dict, List, Tuple, Optional
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
DEFAULT_DISABLE_HEADERS: List[str] = []
DEFAULT_IPV4_HOSTNAME = '127.0.0.1'
DEFAULT_IPV6_HOSTNAME = '::'
DEFAULT_PORT = 8899
DEFAULT_IPV4 = False
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


def text_(s, encoding='utf-8', errors='strict') -> str:
    """Utility to ensure text-like usability.

    If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, bytes):
        return s.decode(encoding, errors)
    return s


def bytes_(s, encoding='utf-8', errors='strict') -> bytes:
    """Utility to ensure binary-like usability.

    If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s


version = bytes_(__version__)
CRLF, COLON, WHITESPACE, COMMA = b'\r\n', b':', b' ', ','
PROXY_AGENT_HEADER = b'Proxy-agent: proxy.py v' + version


class TcpConnection:
    """TCP server/client connection abstraction."""

    types = namedtuple('TcpConnectionTypes', (
        'SERVER',
        'CLIENT',
    ))(1, 2)

    def __init__(self, what: types):
        self.conn: Optional[socket.socket] = None
        self.buffer: bytes = b''
        self.closed: bool = False
        self.what: TcpConnection.types = what

    def send(self, data: bytes) -> int:
        """Users must handle BrokenPipeError exceptions"""
        return self.conn.send(data)

    def recv(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> Optional[bytes]:
        try:
            data: bytes = self.conn.recv(buffer_size)
            if len(data) > 0:
                logger.debug('received %d bytes from %s' % (len(data), self.what))
                return data
        except socket.error as e:
            if e.errno == errno.ECONNRESET:
                logger.debug('%r' % e)
            else:
                logger.exception(
                    'Exception while receiving from connection %s %r with reason %r' % (self.what, self.conn, e))
        return None

    def close(self) -> bool:
        if not self.closed:
            self.conn.close()
            self.closed = True
        return self.closed

    def buffer_size(self) -> int:
        return len(self.buffer)

    def has_buffer(self) -> bool:
        return self.buffer_size() > 0

    def queue(self, data) -> int:
        self.buffer += data
        return len(data)

    def flush(self) -> int:
        sent: int = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        logger.debug('flushed %d bytes to %s' % (sent, self.what))
        return sent


class TcpServerConnection(TcpConnection):
    """Establishes connection to destination server."""

    def __init__(self, host: str, port: int):
        super(TcpServerConnection, self).__init__(b'server')
        self.addr: Tuple[str, int] = (host, int(port))

    def __del__(self):
        if self.conn:
            self.close()

    def connect(self) -> None:
        try:
            ip = ipaddress.ip_address(text_(self.addr[0]))
            if ip.version == 4:
                self.conn = socket.create_connection((self.addr[0], self.addr[1]))
            else:
                self.conn = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
                self.conn.connect((self.addr[0], self.addr[1], 0, 0))
        except ValueError:
            # Not a valid IP address, most likely its a domain name.
            self.conn = socket.create_connection((self.addr[0], self.addr[1]))


class TcpClientConnection(TcpConnection):
    """Accepted client connection."""

    def __init__(self, conn: socket.socket, addr: Tuple[str, int]):
        super(TcpClientConnection, self).__init__(b'client')
        self.conn: socket.socket = conn
        self.addr: Tuple[str, int] = addr


class TcpServer:
    """TcpServer server implementation.

    Inheritor MUST implement `handle` method. It accepts an instance of `TcpClientConnection`.
    Optionally, can also implement `setup` and `shutdown` methods for custom bootstrapping and tearing
    down internal state.
    """

    def __init__(self, hostname=DEFAULT_IPV4_HOSTNAME, port=DEFAULT_PORT, backlog=DEFAULT_BACKLOG, ipv4=DEFAULT_IPV4):
        self.port: int = port
        self.backlog: int = backlog
        self.ipv4: bool = ipv4
        self.socket: Optional[socket.socket] = None
        self.running: bool = False
        self.family = socket.AF_INET if self.ipv4 else socket.AF_INET6
        self.hostname: str = hostname if hostname not in [DEFAULT_IPV4_HOSTNAME,
                                                          DEFAULT_IPV6_HOSTNAME] \
            else DEFAULT_IPV4_HOSTNAME if self.ipv4 else DEFAULT_IPV6_HOSTNAME

    def setup(self) -> None:
        pass

    def handle(self, client: TcpClientConnection):
        raise NotImplementedError()

    def shutdown(self) -> None:
        pass

    def stop(self) -> None:
        self.running = False

    def run(self):
        self.running = True
        self.setup()
        try:
            self.socket = socket.socket(self.family, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(self.backlog)
            logger.info('Started server on %s:%d' % (self.hostname, self.port))
            while self.running:
                r, w, x = select.select([self.socket], [], [], 1)
                if self.socket in r:
                    conn, addr = self.socket.accept()
                    client = TcpClientConnection(conn, addr)
                    self.handle(client)
        except Exception as e:
            logger.exception('Exception while running the server %r' % e)
        finally:
            self.shutdown()
            logger.info('Closing server socket')
            self.socket.close()


class MultiCoreRequestDispatcher(TcpServer):
    """MultiCoreRequestDispatcher.

    Pre-spawns worker process to utilize all cores available on the system.  Accepted `TcpClientConnection` is
    dispatched over a queue to workers.  One of the worker picks up the work and starts a new thread to handle the
    client request.
    """

    def __init__(self, hostname=DEFAULT_IPV4_HOSTNAME, port=DEFAULT_PORT, backlog=DEFAULT_BACKLOG,
                 num_workers=DEFAULT_NUM_WORKERS, ipv4=DEFAULT_IPV4, config=None):
        super(MultiCoreRequestDispatcher, self).__init__(hostname, port, backlog, ipv4)

        self.num_workers: int = multiprocessing.cpu_count()
        if num_workers > 0:
            self.num_workers = num_workers
        self.workers: List[Worker] = []
        self.work_queues: List[multiprocessing.Queue] = []
        self.current_worker_id = 0

        self.config: HttpProtocolConfig = config

    def setup(self):
        logger.info('Starting %d workers' % self.num_workers)
        for worker_id in range(self.num_workers):
            work_queue = multiprocessing.Queue()

            worker = Worker(work_queue, self.config)
            worker.daemon = True
            worker.start()

            self.workers.append(worker)
            self.work_queues.append(work_queue)

    def handle(self, client: TcpClientConnection):
        # Dispatch in round robin fashion
        work_queue = self.work_queues[self.current_worker_id]
        logging.debug('Dispatched client request to worker id %d', self.current_worker_id)
        self.current_worker_id += 1
        self.current_worker_id %= self.num_workers
        work_queue.put((Worker.operations.HTTP_PROTOCOL, client))

    def shutdown(self):
        logger.info('Shutting down %d workers' % self.num_workers)
        for work_queue in self.work_queues:
            work_queue.put((Worker.operations.SHUTDOWN, None))
        for worker in self.workers:
            worker.join()


class Worker(multiprocessing.Process):
    """Generic worker class implementation.

    Worker instance accepts (operation, payload) over work queue and
    depending upon requested operation starts a new thread to handle the work.
    """

    operations = namedtuple('WorkerOperations', (
        'HTTP_PROTOCOL',
        'SHUTDOWN',
    ))(1, 2)

    def __init__(self, work_queue, config=None):
        super(Worker, self).__init__()
        self.work_queue: multiprocessing.Queue = work_queue
        self.config: HttpProtocolConfig = config

    def run(self):
        while True:
            try:
                op, payload = self.work_queue.get(True, 1)
                if op == Worker.operations.HTTP_PROTOCOL:
                    proxy = HttpProtocolHandler(payload, config=self.config)
                    proxy.setDaemon(True)
                    proxy.start()
                elif op == Worker.operations.SHUTDOWN:
                    break
            except queue.Empty:
                pass
            # Safeguard against https://gist.github.com/abhinavsingh/b8d4266ff4f38b6057f9c50075e8cd75
            except ConnectionRefusedError:
                pass
            except KeyboardInterrupt:
                break


class ChunkParser:
    """HTTP chunked encoding response parser."""

    states = namedtuple('ChunkParserStates', (
        'WAITING_FOR_SIZE',
        'WAITING_FOR_DATA',
        'COMPLETE'
    ))(1, 2, 3)

    def __init__(self):
        self.state = ChunkParser.states.WAITING_FOR_SIZE
        self.body: bytes = b''  # Parsed chunks
        self.chunk: bytes = b''  # Partial chunk received
        self.size: int = None  # Expected size of next following chunk

    def parse(self, raw: bytes):
        more = True if len(raw) > 0 else False
        while more:
            more, raw = self.process(raw)

    def process(self, raw: bytes):
        if self.state == ChunkParser.states.WAITING_FOR_SIZE:
            # Consume prior chunk in buffer
            # in case chunk size without CRLF was received
            raw = self.chunk + raw
            self.chunk = b''
            # Extract following chunk data size
            line, raw = HttpParser.split(raw)
            if not line:  # CRLF not received
                self.chunk = raw
                raw = b''
            else:
                self.size = int(line, 16)
                self.state = ChunkParser.states.WAITING_FOR_DATA
        elif self.state == ChunkParser.states.WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += raw[:remaining]
            raw = raw[remaining:]
            if len(self.chunk) == self.size:
                raw = raw[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = ChunkParser.states.COMPLETE
                else:
                    self.state = ChunkParser.states.WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(raw) > 0, raw


class HttpParser:
    """HTTP request/response parser."""

    states = namedtuple('HttpParserStates', (
        'INITIALIZED',
        'LINE_RCVD',
        'RCVING_HEADERS',
        'HEADERS_COMPLETE',
        'RCVING_BODY',
        'COMPLETE'))(1, 2, 3, 4, 5, 6)

    types = namedtuple('HttpParserTypes', (
        'REQUEST_PARSER',
        'RESPONSE_PARSER'
    ))(1, 2)

    def __init__(self, parser_type):
        assert parser_type in (HttpParser.types.REQUEST_PARSER, HttpParser.types.RESPONSE_PARSER)
        self.type: HttpParser.types = parser_type
        self.state: HttpParser.states = HttpParser.states.INITIALIZED

        # Raw bytes as passed to parse(raw) method and its total size
        self.bytes: bytes = b''
        self.total_size: int = 0

        # Buffer to hold unprocessed bytes
        self.buffer: bytes = b''

        self.headers: Dict[bytes, Tuple[bytes, bytes]] = dict()

        # Can simply be b'', then set type as bytes?
        self.body = None

        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

        self.chunk_parser = None

        # This cleans up developer APIs as Python urlparse.urlsplit behaves differently
        # for incoming proxy request and incoming web request.  Web request is the one
        # which is broken.
        self.host = None
        self.port = None

    def set_host_port(self):
        if self.type == HttpParser.types.REQUEST_PARSER:
            if self.method == b'CONNECT':
                u = urlparse.urlsplit(b'//' + self.url.path)
                self.host, self.port = u.hostname, u.port
            elif self.url:
                self.host, self.port = self.url.hostname, self.url.port \
                    if self.url.port else 80
            else:
                raise Exception('Invalid request\n%s' % self.bytes)

    def is_chunked_encoded_response(self):
        return self.type == HttpParser.types.RESPONSE_PARSER and b'transfer-encoding' in self.headers and \
               self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    def parse(self, raw):
        self.bytes += raw
        self.total_size += len(raw)

        # Prepend past buffer
        raw = self.buffer + raw
        self.buffer = b''

        more = True if len(raw) > 0 else False
        while more:
            more, raw = self.process(raw)
        self.buffer = raw

    def process(self, raw):
        if self.state in (HttpParser.states.HEADERS_COMPLETE,
                          HttpParser.states.RCVING_BODY,
                          HttpParser.states.COMPLETE) and \
                (self.method == b'POST' or self.type == HttpParser.types.RESPONSE_PARSER):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HttpParser.states.RCVING_BODY
                self.body += raw
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HttpParser.states.COMPLETE
            elif self.is_chunked_encoded_response():
                if not self.chunk_parser:
                    self.chunk_parser = ChunkParser()
                self.chunk_parser.parse(raw)
                if self.chunk_parser.state == ChunkParser.states.COMPLETE:
                    self.body = self.chunk_parser.body
                    self.state = HttpParser.states.COMPLETE

            return False, b''

        line, raw = HttpParser.split(raw)
        if line is False:
            return line, raw

        if self.state == HttpParser.states.INITIALIZED:
            self.process_line(line)
        elif self.state in (HttpParser.states.LINE_RCVD, HttpParser.states.RCVING_HEADERS):
            self.process_header(line)

        # When connect request is received without a following host header
        # See `TestHttpParser.test_connect_request_without_host_header_request_parse` for details
        if self.state == HttpParser.states.LINE_RCVD and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'CONNECT' and \
                raw == CRLF:
            self.state = HttpParser.states.COMPLETE

        # When raw request has ended with \r\n\r\n and no more http headers are expected
        # See `TestHttpParser.test_request_parse_without_content_length` and
        # `TestHttpParser.test_response_parse_without_content_length` for details
        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method != b'POST' and \
                self.bytes.endswith(CRLF * 2):
            self.state = HttpParser.states.COMPLETE
        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'POST' and \
                (b'content-length' not in self.headers or
                 (b'content-length' in self.headers and
                  int(self.headers[b'content-length'][1]) == 0)) and \
                self.bytes.endswith(CRLF * 2):
            self.state = HttpParser.states.COMPLETE

        return len(raw) > 0, raw

    def process_line(self, raw):
        line = raw.split(WHITESPACE)
        if self.type == HttpParser.types.REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self.set_host_port()
        self.state = HttpParser.states.LINE_RCVD

    def process_header(self, raw):
        if len(raw) == 0:
            if self.state == HttpParser.states.RCVING_HEADERS:
                self.state = HttpParser.states.HEADERS_COMPLETE
            elif self.state == HttpParser.states.LINE_RCVD:
                self.state = HttpParser.states.RCVING_HEADERS
        else:
            self.state = HttpParser.states.RCVING_HEADERS
            parts = raw.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)

    def build_url(self):
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

    def build(self, disable_headers=None):
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS

        req = b' '.join([self.method, self.build_url(), self.version])
        req += CRLF

        for k in self.headers:
            if k.lower() not in disable_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1]) + CRLF

        req += CRLF
        if self.body:
            req += self.body

        return req

    @staticmethod
    def build_header(k, v):
        return k + b': ' + v

    @staticmethod
    def split(raw):
        pos = raw.find(CRLF)
        if pos == -1:
            return False, raw
        line = raw[:pos]
        raw = raw[pos + len(CRLF):]
        return line, raw

    ###################################################################################
    # HttpParser was originally written to parse the incoming raw Http requests.
    # Since request / response objects passed to HttpProtocolBasePlugin methods
    # are also HttpParser objects, methods below were added to simplify developer API.
    ####################################################################################

    def has_upstream_server(self):
        """Host field SHOULD be None for incoming local WebServer requests."""
        return True if self.host is not None else False

    def add_header(self, key: bytes, value: bytes) -> None:
        self.headers[key] = (key, value)

    def add_headers(self, headers: List[Tuple[bytes, bytes]]) -> None:
        for (key, value) in headers:
            self.add_header(key, value)

    def del_header(self, header: bytes) -> None:
        if header in self.headers:
            del self.headers[header]

    def del_headers(self, headers: List[bytes]) -> None:
        for key in headers:
            self.del_header(key)


class HttpProtocolException(Exception):
    """Top level HttpProtocolException exception class.

    All exceptions raised during execution of Http request lifecycle MUST
    inherit HttpProtocolException base class. Implement response() method
    to optionally return custom response to client."""

    def __init__(self):
        pass

    def response(self, request: HttpParser) -> bytes:
        pass


class HttpRequestRejected(HttpProtocolException):
    """Generic exception that can be used to reject the client requests.

    Connections can either be dropped/closed or optionally an
    HTTP status code can be returned."""

    def __init__(self, status_code: bytes = None, body: bytes = None):
        super(HttpRequestRejected, self).__init__()
        self.status_code: bytes = status_code
        self.body: bytes = body

    def response(self, _request: HttpParser) -> bytes:
        pkt = []
        if self.status_code:
            pkt.append(b'HTTP/1.1 ' + self.status_code)
            pkt.append(PROXY_AGENT_HEADER)
        if self.body:
            pkt.append(b'Content-Length: ' + bytes_(str(len(self.body))))
            pkt.append(CRLF)
            pkt.append(self.body)
        else:
            if len(pkt) > 0:
                pkt.append(CRLF)
        return CRLF.join(pkt) if len(pkt) > 0 else None


class HttpProtocolConfig:
    """Holds various configuration values applicable to HttpProtocolHandler.

    This config class helps us avoid passing around bunch of key/value pairs across methods.
    """

    def __init__(self, auth_code=DEFAULT_BASIC_AUTH, server_recvbuf_size=DEFAULT_SERVER_RECVBUF_SIZE,
                 client_recvbuf_size=DEFAULT_CLIENT_RECVBUF_SIZE, pac_file=DEFAULT_PAC_FILE,
                 pac_file_url_path=DEFAULT_PAC_FILE_URL_PATH, plugins=None, disable_headers=None):
        self.auth_code = auth_code
        self.server_recvbuf_size = server_recvbuf_size
        self.client_recvbuf_size = client_recvbuf_size
        self.pac_file = pac_file
        self.pac_file_url_path = pac_file_url_path
        if plugins is None:
            plugins = {}
        self.plugins: Dict[str, List] = plugins
        if disable_headers is None:
            disable_headers = DEFAULT_DISABLE_HEADERS
        self.disable_headers = disable_headers


class HttpProtocolBasePlugin:
    """Base HttpProtocolHandler Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(self, config: HttpProtocolConfig, client: TcpClientConnection, request: HttpParser):
        self.config: HttpProtocolConfig = config
        self.client: TcpClientConnection = client
        self.request: HttpParser = request

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__

    def get_descriptors(self) -> Tuple[List, List, List]:
        return [], [], []

    def flush_to_descriptors(self, w) -> None:
        pass

    def read_from_descriptors(self, r) -> None:
        pass

    def on_client_data(self, raw: bytes) -> bytes:
        return raw

    def on_request_complete(self) -> None:
        """Called right after client request parser has reached COMPLETE state."""
        pass

    def handle_response_chunk(self, chunk: bytes) -> bytes:
        """Handle data chunks as received from the server.

        Return optionally modified chunk to return back to client."""
        return chunk

    def access_log(self) -> None:
        pass

    def on_client_connection_close(self) -> None:
        pass


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
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)


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


class HttpProxyBasePlugin:
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(self, config: HttpProtocolConfig, client: TcpClientConnection, request: HttpParser):
        self.config = config
        self.client = client
        self.request = request

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__

    def before_upstream_connection(self):
        """Handler called just before Proxy upstream connection is established.

        Raise HttpRequestRejected to drop the connection."""
        pass

    def on_upstream_connection(self):
        """Handler called right after upstream connection has been established."""
        pass

    def handle_upstream_response(self, raw):
        """Handled called right after reading response from upstream server and
        before queuing that response to client.

        Optionally return modified response to queue for client."""
        return raw


class HttpProxyPlugin(HttpProtocolBasePlugin):
    """HttpProtocolHandler plugin which implements HttpProxy specifications."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 200 Connection established',
        CRLF
    ])

    def __init__(self, config: HttpProtocolConfig, client: TcpClientConnection, request: HttpParser):
        super(HttpProxyPlugin, self).__init__(config, client, request)
        self.server = None
        self.response = HttpParser(HttpParser.types.RESPONSE_PARSER)

        self.plugins: Dict[str, HttpProxyBasePlugin] = {}
        if 'HttpProxyBasePlugin' in self.config.plugins:
            for klass in self.config.plugins['HttpProxyBasePlugin']:
                instance = klass(self.config, self.client, self.request)
                self.plugins[instance.name()] = instance

    def get_descriptors(self):
        if not self.request.has_upstream_server():
            return [], [], []

        r, w, x = [], [], []
        if self.server and not self.server.closed:
            r.append(self.server.conn)
        if self.server and not self.server.closed and self.server.has_buffer():
            w.append(self.server.conn)
        return r, w, x

    def flush_to_descriptors(self, w):
        if not self.request.has_upstream_server():
            return

        if self.server and not self.server.closed and self.server.conn in w:
            logger.debug('Server is ready for writes, flushing server buffer')
            try:
                self.server.flush()
            except BrokenPipeError:
                logging.error('BrokenPipeError when flushing buffer for server')
                return True

    def read_from_descriptors(self, r):
        if not self.request.has_upstream_server():
            return

        if self.server and not self.server.closed and self.server.conn in r:
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

    def on_client_connection_close(self):
        if not self.request.has_upstream_server():
            return

        if self.server:
            logger.debug(
                'Closed server connection with pending server buffer size %d bytes' % self.server.buffer_size())
            if not self.server.closed:
                self.server.close()

    def on_client_data(self, raw):
        if not self.request.has_upstream_server():
            return raw

        if self.server and not self.server.closed:
            self.server.queue(raw)
            return None
        else:
            return raw

    def on_request_complete(self):
        if not self.request.has_upstream_server():
            return

        for plugin in self.plugins.values():
            plugin.before_upstream_connection()

        self.authenticate(self.request.headers)
        self.connect_upstream(self.request.host, self.request.port)

        for plugin in self.plugins.values():
            plugin.on_upstream_connection()

        # for http connect methods (https requests)
        # queue appropriate response for client
        # notifying about established connection
        if self.request.method == b'CONNECT':
            self.client.queue(HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        # for general http requests, re-build request packet
        # and queue for the server with appropriate headers
        else:
            # remove args.disable_headers before dispatching to upstream
            self.request.add_headers([(b'Via', b'1.1 proxy.py v%s' % version), (b'Connection', b'Close')])
            self.request.del_headers([b'proxy-authorization', b'proxy-connection', b'connection', b'keep-alive'])
            self.server.queue(self.request.build(disable_headers=self.config.disable_headers))

    def access_log(self):
        if not self.request.has_upstream_server():
            return

        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s - %s bytes' % (self.client.addr[0], self.client.addr[1],
                                                 text_(self.request.method), text_(host),
                                                 text_(port), self.response.total_size))
        elif self.request.method:
            logger.info('%s:%s - %s %s:%s%s - %s %s - %s bytes' % (
                self.client.addr[0], self.client.addr[1], text_(self.request.method), text_(host), port,
                text_(self.request.build_url()), text_(self.response.code), text_(self.response.reason),
                self.response.total_size))

    def authenticate(self, headers):
        if self.config.auth_code:
            if b'proxy-authorization' not in headers or \
                    headers[b'proxy-authorization'][1] != self.config.auth_code:
                raise ProxyAuthenticationFailed()

    def connect_upstream(self, host, port):
        self.server = TcpServerConnection(host, port)
        try:
            logger.debug('Connecting to upstream %s:%s' % (host, port))
            self.server.connect()
            logger.debug('Connected to upstream %s:%s' % (host, port))
        except Exception as e:  # TimeoutError, socket.gaierror
            self.server.closed = True
            raise ProxyConnectionFailed(host, port, repr(e))


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

    def __init__(self, config: HttpProtocolConfig, client: TcpClientConnection, request: HttpParser):
        super(HttpWebServerPlugin, self).__init__(config, client, request)
        if self.config.pac_file:
            try:
                with open(self.config.pac_file, 'rb') as f:
                    logger.debug('Will serve pac file from disk')
                    self.pac_file_content = f.read()
            except IOError:
                logger.debug('Will serve pac file content from buffer')
                self.pac_file_content = self.config.pac_file

    def on_request_complete(self):
        if self.request.has_upstream_server():
            return

        if self.config.pac_file and \
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

    def access_log(self):
        if self.request.has_upstream_server():
            return
        logger.info('%s:%s - %s %s' % (self.client.addr[0], self.client.addr[1],
                                       text_(self.request.method), text_(self.request.build_url())))


class HttpProtocolHandler(threading.Thread):
    """HTTP, HTTPS, HTTP2, WebSockets protocol handler.

    Accepts `Client` connection object and manages HttpProtocolBasePlugin invocations.
    """

    def __init__(self, client, config=None):
        super(HttpProtocolHandler, self).__init__()
        self.start_time = self.now()
        self.last_activity = self.start_time

        self.client = client
        self.config = config if config else HttpProtocolConfig()
        self.request = HttpParser(HttpParser.types.REQUEST_PARSER)

        self.plugins: Dict[str, HttpProtocolBasePlugin] = {}
        if 'HttpProtocolBasePlugin' in self.config.plugins:
            for klass in self.config.plugins['HttpProtocolBasePlugin']:
                instance = klass(self.config, self.client, self.request)
                self.plugins[instance.name()] = instance

    @staticmethod
    def now():
        return datetime.datetime.utcnow()

    def connection_inactive_for(self):
        return (self.now() - self.last_activity).seconds

    def is_connection_inactive(self):
        return self.connection_inactive_for() > 30

    def run_once(self):
        """Returns True if proxy must teardown."""
        # Prepare list of descriptors
        read_desc, write_desc, err_desc = [self.client.conn], [], []
        if self.client.has_buffer():
            write_desc.append(self.client.conn)

        # HttpProtocolBasePlugin.get_descriptors
        for plugin in self.plugins.values():
            plugin_read_desc, plugin_write_desc, plugin_err_desc = plugin.get_descriptors()
            read_desc += plugin_read_desc
            write_desc += plugin_write_desc
            err_desc += plugin_err_desc

        readable, writable, errored = select.select(read_desc, write_desc, err_desc, 1)

        # Flush buffer for ready to write sockets
        if self.client.conn in writable:
            logger.debug('Client is ready for writes, flushing client buffer')
            try:
                self.client.flush()
            except BrokenPipeError:
                logging.error('BrokenPipeError when flushing buffer for client')
                return True

        for plugin in self.plugins.values():
            plugin.flush_to_descriptors(writable)

        # Read from ready to read sockets
        if self.client.conn in readable:
            logger.debug('Client is ready for reads, reading')
            client_data = self.client.recv(self.config.client_recvbuf_size)
            self.last_activity = self.now()
            if not client_data:
                logger.debug('Client closed connection, tearing down...')
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
                    if self.request.state == HttpParser.states.COMPLETE:
                        # HttpProtocolBasePlugin.on_request_complete
                        for plugin in self.plugins.values():
                            # TODO: Cleanup by not returning True for teardown cases
                            plugin_response = plugin.on_request_complete()
                            if type(plugin_response) is bool:
                                return True
                # ProxyAuthenticationFailed, ProxyConnectionFailed, HttpRequestRejected
                except HttpProtocolException as e:
                    # logger.exception(e)
                    response = e.response(self.request)
                    if response:
                        self.client.queue(response)
                        # But is client also ready for writes?
                        self.client.flush()
                    raise e

        # HttpProtocolBasePlugin.read_from_descriptors
        for plugin in self.plugins.values():
            teardown = plugin.read_from_descriptors(readable)
            if teardown:
                return True

        # Teardown if client buffer is empty and connection is inactive
        if self.client.buffer_size() == 0:
            if self.is_connection_inactive():
                logger.debug('Client buffer is empty and maximum inactivity has reached '
                             'between client and server connection, tearing down...')
                return True

    def run(self):
        logger.debug('Proxying connection %r' % self.client.conn)
        try:
            while True:
                teardown = self.run_once()
                if teardown:
                    break
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.client.conn, e))
        finally:
            for plugin in self.plugins.values():
                plugin.access_log()

            self.client.close()
            logger.debug('Closed client connection with pending '
                         'client buffer size %d bytes' % self.client.buffer_size())
            for plugin in self.plugins.values():
                plugin.on_client_connection_close()

            logger.debug('Closed proxy for connection %r '
                         'at address %r' % (self.client.conn, self.client.addr))


def is_py3() -> bool:
    """Exists only to avoid mocking sys.version_info in tests."""
    return sys.version_info[0] == 3


def set_open_file_limit(soft_limit):
    """Configure open file description soft limit on supported OS."""
    if os.name != 'nt':  # resource module not available on Windows OS
        curr_soft_limit, curr_hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if curr_soft_limit < soft_limit < curr_hard_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
            logger.debug('Open file descriptor soft limit set to %d' % soft_limit)


def load_plugins(plugins: str) -> Dict[str, List]:
    """Accepts a comma separated list of Python modules and returns
    a list of respective Python classes."""
    p: Dict[str, List] = {
        'HttpProtocolBasePlugin': [],
        'HttpProxyBasePlugin': []
    }
    for plugin in plugins.split(COMMA):
        plugin = plugin.strip()
        if plugin == '':
            continue
        module_name, klass_name = plugin.rsplit('.', 1)
        module = importlib.import_module(module_name)
        klass = getattr(module, klass_name)
        base_klass = inspect.getmro(klass)[::-1][1:][0]
        p[base_klass.__name__].append(klass)
        logging.info('Loaded plugin %s', klass)
    return p


def setup_logger(log_file=DEFAULT_LOG_FILE, log_level=DEFAULT_LOG_LEVEL, log_format=DEFAULT_LOG_FORMAT):
    ll = getattr(
        logging,
        {'D': 'DEBUG',
         'I': 'INFO',
         'W': 'WARNING',
         'E': 'ERROR',
         'C': 'CRITICAL'}[log_level.upper()[0]])
    if log_file:
        logging.basicConfig(filename=log_file, filemode='a', level=ll, format=log_format)
    else:
        logging.basicConfig(level=ll, format=log_format)


def init_parser() -> argparse.ArgumentParser:
    """Initializes and returns argument parser."""
    parser = argparse.ArgumentParser(
        description='proxy.py v%s' % __version__,
        epilog='Proxy.py not working? Report at: %s/issues/new' % __homepage__
    )
    # Argument names are ordered alphabetically.
    parser.add_argument('--backlog', type=int, default=DEFAULT_BACKLOG,
                        help='Default: 100. Maximum number of pending connections to proxy server')
    parser.add_argument('--basic-auth', type=str, default=DEFAULT_BASIC_AUTH,
                        help='Default: No authentication. Specify colon separated user:password '
                             'to enable basic authentication.')
    parser.add_argument('--client-recvbuf-size', type=int, default=DEFAULT_CLIENT_RECVBUF_SIZE,
                        help='Default: 1 MB. Maximum amount of data received from the '
                             'client in a single recv() operation. Bump this '
                             'value for faster uploads at the expense of '
                             'increased RAM.')
    parser.add_argument('--disable-headers', type=str, default=COMMA.join(DEFAULT_DISABLE_HEADERS),
                        help='Default: None.  Comma separated list of headers to remove before '
                             'dispatching client request to upstream server.')
    parser.add_argument('--disable-http-proxy', action='store_true', default=DEFAULT_DISABLE_HTTP_PROXY,
                        help='Default: False.  Whether to disable proxy.HttpProxyPlugin.')
    parser.add_argument('--hostname', type=str, default=DEFAULT_IPV4_HOSTNAME,
                        help='Default: 127.0.0.1. Server IP address.')
    parser.add_argument('--ipv4', action='store_true', default=DEFAULT_IPV4,
                        help='Whether to listen on IPv4 address. '
                             'By default server only listens on IPv6.')
    parser.add_argument('--enable-web-server', action='store_true', default=DEFAULT_ENABLE_WEB_SERVER,
                        help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.')
    parser.add_argument('--log-level', type=str, default=DEFAULT_LOG_LEVEL,
                        help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
                             'Both upper and lowercase values are allowed. '
                             'You may also simply use the leading character e.g. --log-level d')
    parser.add_argument('--log-file', type=str, default=DEFAULT_LOG_FILE,
                        help='Default: sys.stdout. Log file destination.')
    parser.add_argument('--log-format', type=str, default=DEFAULT_LOG_FORMAT,
                        help='Log format for Python logger.')
    parser.add_argument('--num-workers', type=int, default=DEFAULT_NUM_WORKERS,
                        help='Defaults to number of CPU cores.')
    parser.add_argument('--open-file-limit', type=int, default=DEFAULT_OPEN_FILE_LIMIT,
                        help='Default: 1024. Maximum number of files (TCP connections) '
                             'that proxy.py can open concurrently.')
    parser.add_argument('--pac-file', type=str, default=DEFAULT_PAC_FILE,
                        help='A file (Proxy Auto Configuration) or string to serve when '
                             'the server receives a direct file request. '
                             'Using this option enables proxy.HttpWebServerPlugin.')
    parser.add_argument('--pac-file-url-path', type=str, default=DEFAULT_PAC_FILE_URL_PATH,
                        help='Default: %s. Web server path to serve the PAC file.' % text_(DEFAULT_PAC_FILE_URL_PATH))
    parser.add_argument('--pid-file', type=str, default=DEFAULT_PID_FILE,
                        help='Default: None. Save parent process ID to a file.')
    parser.add_argument('--plugins', type=str, default=DEFAULT_PLUGINS, help='Comma separated plugins')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help='Default: 8899. Server port.')
    parser.add_argument('--server-recvbuf-size', type=int, default=DEFAULT_SERVER_RECVBUF_SIZE,
                        help='Default: 1 MB. Maximum amount of data received from the '
                             'server in a single recv() operation. Bump this '
                             'value for faster downloads at the expense of '
                             'increased RAM.')
    parser.add_argument('--version', '-v', action='store_true', default=DEFAULT_VERSION,
                        help='Prints proxy.py version.')
    return parser


def main(args) -> None:
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

    parser = init_parser()
    args = parser.parse_args(args)
    if args.version:
        print(text_(version))
        sys.exit(0)

    try:
        setup_logger(args.log_file, args.log_level, args.log_format)
        set_open_file_limit(args.open_file_limit)

        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        config = HttpProtocolConfig(auth_code=auth_code,
                                    server_recvbuf_size=args.server_recvbuf_size,
                                    client_recvbuf_size=args.client_recvbuf_size,
                                    pac_file=args.pac_file,
                                    pac_file_url_path=args.pac_file_url_path,
                                    disable_headers=[header.lower() for header in args.disable_headers.split(COMMA) if
                                                     header.strip() != ''])
        if config.pac_file is not None:
            args.enable_web_server = True

        default_plugins = ''
        if not args.disable_http_proxy:
            default_plugins += 'proxy.HttpProxyPlugin,'
        if args.enable_web_server:
            default_plugins += 'proxy.HttpWebServerPlugin,'
        config.plugins = load_plugins('%s%s' % (default_plugins, args.plugins))

        server = MultiCoreRequestDispatcher(hostname=args.hostname,
                                            port=args.port,
                                            backlog=args.backlog,
                                            ipv4=args.ipv4,
                                            num_workers=args.num_workers,
                                            config=config)
        if args.pid_file:
            with open(args.pid_file, 'wb') as pid_file:
                pid_file.write(bytes_(str(os.getpid())))
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        if args.pid_file:
            if os.path.exists(args.pid_file):
                os.remove(args.pid_file)


if __name__ == '__main__':
    main(sys.argv[1:])
