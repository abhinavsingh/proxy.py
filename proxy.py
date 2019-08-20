#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~

    HTTP, HTTPS, HTTP2 and WebSockets Proxy Server in Python.

    :copyright: (c) 2013-2020 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import argparse
import base64
import datetime
import errno
import importlib
import logging
import multiprocessing
import os
import select
import socket
import sys
import threading
from collections import namedtuple

if os.name != 'nt':
    import resource

VERSION = (0, 4)
__version__ = '.'.join(map(str, VERSION[0:2]))
__description__ = 'Lightweight HTTP, HTTPS, WebSockets Proxy Server in a single Python file'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

logger = logging.getLogger(__name__)

PY3 = sys.version_info[0] == 3

if PY3:  # pragma: no cover
    text_type = str
    binary_type = bytes
    from urllib import parse as urlparse
    import queue
else:  # pragma: no cover
    text_type = unicode
    binary_type = str
    import urlparse
    import Queue as queue

# Defaults
DEFAULT_BACKLOG = 100
DEFAULT_BASIC_AUTH = None
DEFAULT_BUFFER_SIZE = 8192
DEFAULT_CLIENT_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_SERVER_RECVBUF_SIZE = DEFAULT_BUFFER_SIZE
DEFAULT_IPV4_HOSTNAME = '127.0.0.1'
DEFAULT_IPV6_HOSTNAME = '::'
DEFAULT_PORT = 8899
DEFAULT_IPV4 = False
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_OPEN_FILE_LIMIT = 1024
DEFAULT_PAC_FILE = None
DEFAULT_NUM_WORKERS = 0
DEFAULT_PLUGINS = []
DEFAULT_LOG_FORMAT = '%(asctime)s - %(levelname)s - pid:%(process)d - %(funcName)s:%(lineno)d - %(message)s'

UNDER_TEST = False


def text_(s, encoding='utf-8', errors='strict'):  # pragma: no cover
    """Utility to ensure text-like usability.

    If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    return s


def bytes_(s, encoding='utf-8', errors='strict'):  # pragma: no cover
    """Utility to ensure binary-like usability.

    If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, text_type):
        return s.encode(encoding, errors)
    return s


version = bytes_(__version__)
CRLF, COLON, SP = b'\r\n', b':', b' '
PROXY_AGENT_HEADER = b'Proxy-agent: proxy.py v' + version

PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = CRLF.join([
    b'HTTP/1.1 200 Connection established',
    PROXY_AGENT_HEADER,
    CRLF
])

PAC_FILE_RESPONSE_PREFIX = CRLF.join([
    b'HTTP/1.1 200 OK',
    b'Content-Type: application/x-ns-proxy-autoconfig',
    b'Connection: close',
    CRLF
])


class ChunkParser(object):
    """HTTP chunked encoding response parser."""

    states = namedtuple('ChunkParserStates', (
        'WAITING_FOR_SIZE',
        'WAITING_FOR_DATA',
        'COMPLETE'
    ))(1, 2, 3)

    def __init__(self):
        self.state = ChunkParser.states.WAITING_FOR_SIZE
        self.body = b''  # Parsed chunks
        self.chunk = b''  # Partial chunk received
        self.size = None  # Expected size of next following chunk

    def parse(self, data):
        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)

    def process(self, data):
        if self.state == ChunkParser.states.WAITING_FOR_SIZE:
            # Consume prior chunk in buffer
            # in case chunk size without CRLF was received
            data = self.chunk + data
            self.chunk = b''
            # Extract following chunk data size
            line, data = HttpParser.split(data)
            if not line:  # CRLF not received
                self.chunk = data
                data = b''
            else:
                self.size = int(line, 16)
                self.state = ChunkParser.states.WAITING_FOR_DATA
        elif self.state == ChunkParser.states.WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = ChunkParser.states.COMPLETE
                else:
                    self.state = ChunkParser.states.WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(data) > 0, data


class HttpParser(object):
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
        self.type = parser_type
        self.state = HttpParser.states.INITIALIZED

        self.raw = b''
        self.buffer = b''

        self.headers = dict()
        self.body = None

        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None

        self.chunk_parser = None

    def is_chunked_encoded_response(self):
        return self.type == HttpParser.types.RESPONSE_PARSER and \
               b'transfer-encoding' in self.headers and \
               self.headers[b'transfer-encoding'][1].lower() == b'chunked'

    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = b''

        more = True if len(data) > 0 else False
        while more:
            more, data = self.process(data)
        self.buffer = data

    def process(self, data):
        if self.state in (HttpParser.states.HEADERS_COMPLETE,
                          HttpParser.states.RCVING_BODY,
                          HttpParser.states.COMPLETE) and \
                (self.method == b'POST' or self.type == HttpParser.types.RESPONSE_PARSER):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HttpParser.states.RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HttpParser.states.COMPLETE
            elif self.is_chunked_encoded_response():
                if not self.chunk_parser:
                    self.chunk_parser = ChunkParser()
                self.chunk_parser.parse(data)
                if self.chunk_parser.state == ChunkParser.states.COMPLETE:
                    self.body = self.chunk_parser.body
                    self.state = HttpParser.states.COMPLETE

            return False, b''

        line, data = HttpParser.split(data)
        if line is False:
            return line, data

        if self.state == HttpParser.states.INITIALIZED:
            self.process_line(line)
        elif self.state in (HttpParser.states.LINE_RCVD, HttpParser.states.RCVING_HEADERS):
            self.process_header(line)

        # When connect request is received without a following host header
        # See `TestHttpParser.test_connect_request_without_host_header_request_parse` for details
        if self.state == HttpParser.states.LINE_RCVD and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'CONNECT' and \
                data == CRLF:
            self.state = HttpParser.states.COMPLETE

        # When raw request has ended with \r\n\r\n and no more http headers are expected
        # See `TestHttpParser.test_request_parse_without_content_length` and
        # `TestHttpParser.test_response_parse_without_content_length` for details
        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method != b'POST' and \
                self.raw.endswith(CRLF * 2):
            self.state = HttpParser.states.COMPLETE
        elif self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                self.method == b'POST' and \
                (b'content-length' not in self.headers or
                 (b'content-length' in self.headers and
                  int(self.headers[b'content-length'][1]) == 0)) and \
                self.raw.endswith(CRLF * 2):
            self.state = HttpParser.states.COMPLETE

        return len(data) > 0, data

    def process_line(self, data):
        line = data.split(SP)
        if self.type == HttpParser.types.REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = b' '.join(line[2:])
        self.state = HttpParser.states.LINE_RCVD

    def process_header(self, data):
        if len(data) == 0:
            if self.state == HttpParser.states.RCVING_HEADERS:
                self.state = HttpParser.states.HEADERS_COMPLETE
            elif self.state == HttpParser.states.LINE_RCVD:
                self.state = HttpParser.states.RCVING_HEADERS
        else:
            self.state = HttpParser.states.RCVING_HEADERS
            parts = data.split(COLON)
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

    def build(self, del_headers=None, add_headers=None):
        req = b' '.join([self.method, self.build_url(), self.version])
        req += CRLF

        if not del_headers:
            del_headers = []
        for k in self.headers:
            if k not in del_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1]) + CRLF

        if not add_headers:
            add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1]) + CRLF

        req += CRLF
        if self.body:
            req += self.body

        return req

    @staticmethod
    def build_header(k, v):
        return k + b': ' + v

    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1:
            return False, data
        line = data[:pos]
        data = data[pos + len(CRLF):]
        return line, data


class TcpConnection(object):
    """TCP server/client connection abstraction."""

    def __init__(self, what):
        self.conn = None
        self.buffer = b''
        self.closed = False
        self.what = what  # server or client

    def send(self, data):
        # TODO: Gracefully handle BrokenPipeError exceptions
        return self.conn.send(data)

    def recv(self, bufsiz=DEFAULT_BUFFER_SIZE):
        try:
            data = self.conn.recv(bufsiz)
            if len(data) == 0:
                logger.debug('rcvd 0 bytes from %s' % self.what)
                return None
            logger.debug('rcvd %d bytes from %s' % (len(data), self.what))
            return data
        except Exception as e:
            if e.errno == errno.ECONNRESET:
                logger.debug('%r' % e)
            else:
                logger.exception(
                    'Exception while receiving from connection %s %r with reason %r' % (self.what, self.conn, e))
            return None

    def close(self):
        self.conn.close()
        self.closed = True

    def buffer_size(self):
        return len(self.buffer)

    def has_buffer(self):
        return self.buffer_size() > 0

    def queue(self, data):
        self.buffer += data

    def flush(self):
        sent = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        logger.debug('flushed %d bytes to %s' % (sent, self.what))


class TcpServerConnection(TcpConnection):
    """Establish connection to destination server."""

    def __init__(self, host, port):
        super(TcpServerConnection, self).__init__(b'server')
        self.addr = (host, int(port))

    def __del__(self):
        if self.conn:
            self.close()

    def connect(self):
        self.conn = socket.create_connection((self.addr[0], self.addr[1]))


class TcpClientConnection(TcpConnection):
    """Accepted client connection."""

    def __init__(self, conn, addr):
        super(TcpClientConnection, self).__init__(b'client')
        self.conn = conn
        self.addr = addr


class ProxyError(Exception):
    """Top level ProxyError exception class.

    All exceptions raised during execution of request lifecycle MUST inherit ProxyError base class.

    Implement response() method to optionally return custom response to client."""

    def __init__(self):
        pass

    def response(self, request):
        pass


class ProxyConnectionFailed(ProxyError):
    """Exception raised when we are unable to establish connection to upstream server."""

    RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 502 Bad Gateway',
        PROXY_AGENT_HEADER,
        b'Content-Length: 11',
        b'Connection: close',
        CRLF
    ]) + b'Bad Gateway'

    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason

    def response(self, _request):
        return self.RESPONSE_PKT

    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)


class ProxyAuthenticationFailed(ProxyError):
    """Exception raised when authentication is enabled and incoming request doesn't present necessary credentials."""

    RESPONSE_PKT = CRLF.join([
        b'HTTP/1.1 407 Proxy Authentication Required',
        PROXY_AGENT_HEADER,
        b'Content-Length: 29',
        b'Connection: close',
        b'Proxy-Authenticate: Basic',
        CRLF
    ]) + b'Proxy Authentication Required'

    def response(self, _request):
        return self.RESPONSE_PKT


class ProxyRequestRejected(ProxyError):
    """Generic exception which can be used to reject client requests.

    Connections can either be dropped/closed or optionally an HTTP status code can also be returned."""

    def __init__(self, status_code=None, body=None):
        super(ProxyRequestRejected, self).__init__()

        self.status_code = status_code
        self.body = body

    def response(self, _request):
        pkt = []
        if self.status_code:
            pkt.append(b'HTTP/1.1 ' + self.status_code)
            pkt.append(PROXY_AGENT_HEADER)
        if self.body:
            pkt.append(b'Content-Length: ' + bytes(len(self.body)))
            pkt.append(CRLF)
            pkt.append(self.body)
        return CRLF.join(pkt) if len(pkt) > 0 else None


class HttpProxyPlugin(object):
    """Base HttpProxy Plugin class."""

    def __init__(self):
        pass

    def handle_request(self, request):
        """Handle client request (HttpParser).

        Return optionally modified client request (HttpParser) object.
        """
        return request

    def handle_response(self, data):
        """Handle data chunks as received from the server."""
        return data


class HttpProxyConfig(object):
    """Holds various configuration values applicable to HttpProxy.

    This config class helps us avoid passing around bunch of key/value pairs across methods.
    """

    def __init__(self, auth_code=DEFAULT_BASIC_AUTH, server_recvbuf_size=DEFAULT_SERVER_RECVBUF_SIZE,
                 client_recvbuf_size=DEFAULT_CLIENT_RECVBUF_SIZE, pac_file=DEFAULT_PAC_FILE, plugins=None):
        self.auth_code = auth_code
        self.server_recvbuf_size = server_recvbuf_size
        self.client_recvbuf_size = client_recvbuf_size
        self.pac_file = pac_file
        if plugins is None:
            plugins = DEFAULT_PLUGINS
        self.plugins = plugins


class HttpProxy(threading.Thread):
    """HTTP proxy implementation.

    Accepts `Client` connection object and act as a proxy between client and server.
    """

    def __init__(self, client, config=None):
        super(HttpProxy, self).__init__()

        self.start_time = self.now()
        self.last_activity = self.start_time

        self.client = client
        self.server = None
        self.config = config if config else HttpProxyConfig()

        self.request = HttpParser(HttpParser.types.REQUEST_PARSER)
        self.response = HttpParser(HttpParser.types.RESPONSE_PARSER)

    @staticmethod
    def now():
        return datetime.datetime.utcnow()

    def connection_inactive_for(self):
        return (self.now() - self.last_activity).seconds

    def is_connection_inactive(self):
        return self.connection_inactive_for() > 30

    def process_request(self, data):
        """Return True to teardown proxy connection."""
        # once we have connection to the server
        # we don't parse the http request packets
        # any further, instead just pipe incoming
        # data from client to server
        if self.server and not self.server.closed:
            self.server.queue(data)
            return False

        # parse http request
        self.request.parse(data)

        # once http request parser has reached the state complete
        # we attempt to establish connection to destination server
        if self.request.state == HttpParser.states.COMPLETE:
            logger.debug('request parser is in state complete')

            # Plugin handle_request
            for plugin in self.config.plugins:
                self.request = plugin.handle_request(self.request)

            if self.config.auth_code:
                if b'proxy-authorization' not in self.request.headers or \
                        self.request.headers[b'proxy-authorization'][1] != self.config.auth_code:
                    raise ProxyAuthenticationFailed()

            if self.request.method == b'CONNECT':
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80
            else:
                raise Exception('Invalid request\n%s' % self.request.raw)

            if host is None and self.config.pac_file:
                self.serve_pac_file()
                return True

            self.server = TcpServerConnection(host, port)
            try:
                logger.debug('connecting to server %s:%s' % (host, port))
                self.server.connect()
                logger.debug('connected to server %s:%s' % (host, port))
            except Exception as e:  # TimeoutError, socket.gaierror
                self.server.closed = True
                raise ProxyConnectionFailed(host, port, repr(e))

            # for http connect methods (https requests)
            # queue appropriate response for client
            # notifying about established connection
            if self.request.method == b'CONNECT':
                self.client.queue(PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
            # for usual http requests, re-build request packet
            # and queue for the server with appropriate headers
            else:
                self.server.queue(self.request.build(
                    del_headers=[b'proxy-authorization', b'proxy-connection', b'connection', b'keep-alive'],
                    add_headers=[(b'Via', b'1.1 proxy.py v%s' % version), (b'Connection', b'Close')]
                ))

    def process_response(self, data):
        # parse incoming response packet
        # only for non-https requests
        if not self.request.method == b'CONNECT':
            self.response.parse(data)

        # queue data for client
        self.client.queue(data)

    def access_log(self):
        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s' % (self.client.addr[0], self.client.addr[1], self.request.method, host, port))
        elif self.request.method:
            logger.info('%s:%s - %s %s:%s%s - %s %s - %s bytes' % (
                self.client.addr[0], self.client.addr[1], text_(self.request.method), text_(host), port,
                text_(self.request.build_url()), text_(self.response.code), text_(self.response.reason),
                len(self.response.raw)))

    def serve_pac_file(self):
        self.client.queue(PAC_FILE_RESPONSE_PREFIX)
        try:
            with open(self.config.pac_file, 'r') as f:
                logger.debug('Serving pac file from disk')
                self.client.queue(f.read())
        except IOError:
            logger.debug('Serving pac file content from buffer')
            self.client.queue(self.config.pac_file)
        self.client.flush()

    def run(self):
        logger.debug('Proxying connection %r' % self.client.conn)
        try:
            while True:
                # Prepare list of descriptors
                rlist, wlist, xlist = [self.client.conn], [], []
                if self.client.has_buffer():
                    wlist.append(self.client.conn)
                if self.server and not self.server.closed:
                    rlist.append(self.server.conn)
                if self.server and not self.server.closed and self.server.has_buffer():
                    wlist.append(self.server.conn)

                r, w, x = select.select(rlist, wlist, xlist, 1)

                # Process ready for writes
                if self.client.conn in w:
                    logger.debug('Client is ready for writes, flushing client buffer')
                    self.client.flush()
                if self.server and not self.server.closed and self.server.conn in w:
                    logger.debug('Server is ready for writes, flushing server buffer')
                    self.server.flush()

                # Process ready for reads
                if self.client.conn in r:
                    logger.debug('Client is ready for reads, reading')
                    data = self.client.recv(self.config.client_recvbuf_size)
                    self.last_activity = self.now()
                    if not data:
                        logger.debug('Client closed connection, tearing down...')
                        break
                    try:
                        teardown = self.process_request(data)
                        if teardown:
                            break
                    except (ProxyAuthenticationFailed, ProxyConnectionFailed, ProxyRequestRejected) as e:
                        logger.exception(e)
                        response = e.response(self.request)
                        if response:
                            # But is client also ready for writes?
                            self.client.queue(response)
                            self.client.flush()
                        break
                if self.server and not self.server.closed and self.server.conn in r:
                    logger.debug('Server is ready for reads, reading')
                    data = self.server.recv(self.config.server_recvbuf_size)
                    self.last_activity = self.now()
                    if not data:
                        logger.debug('Server closed connection, tearing down...')
                        break
                    self.process_response(data)

                # Teardown if client buffer is empty and client is also inactive
                if self.client.buffer_size() == 0:
                    if self.is_connection_inactive():
                        logger.debug('Client buffer is empty and maximum inactivity has reached '
                                     'between client and server connection, tearing down...')
                        break
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.client.conn, e))
        finally:
            self.client.close()
            logger.debug(
                'Closed client connection with pending client buffer size %d bytes' % self.client.buffer_size())
            if self.server:
                logger.debug(
                    'Closed server connection with pending server buffer size %d bytes' % self.server.buffer_size())
                if not self.server.closed:
                    self.server.close()
            self.access_log()
            logger.debug('Closed proxy for connection %r at address %r' % (self.client.conn, self.client.addr))


class TcpServer(object):
    """TcpServer server implementation.

    Inheritor MUST implement `handle` method. It accepts an instance of `TcpClientConnection`.
    Optionally, can also implement `setup` and `shutdown` methods for custom bootstrapping and tearing
    down internal state.
    """

    def __init__(self, hostname=DEFAULT_IPV4_HOSTNAME, port=DEFAULT_PORT, backlog=DEFAULT_BACKLOG, ipv4=DEFAULT_IPV4):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog
        self.ipv4 = ipv4
        self.socket = None
        self.running = False

    def setup(self):
        pass

    def handle(self, client):
        raise NotImplementedError()

    def shutdown(self):
        pass

    def stop(self):
        self.running = False

    def run(self):
        self.running = True
        self.setup()
        try:
            self.socket = socket.socket(socket.AF_INET if self.ipv4 is True else socket.AF_INET6, socket.SOCK_STREAM)
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

        self.worker_queue = multiprocessing.Queue()
        self.num_workers = multiprocessing.cpu_count()
        if num_workers > 0:
            self.num_workers = num_workers
        self.workers = []
        self.config = config

    def setup(self):
        logger.info('Starting %d workers' % self.num_workers)
        for worker_id in range(self.num_workers):
            worker = Worker(self.worker_queue, self.config)
            worker.daemon = True
            worker.start()
            self.workers.append(worker)

    def handle(self, client):
        self.worker_queue.put((Worker.operations.HTTP_PROXY, client))

    def shutdown(self):
        logger.info('Shutting down %d workers' % self.num_workers)
        for worker_id in range(self.num_workers):
            self.worker_queue.put((Worker.operations.SHUTDOWN, None))
        for worker_id in range(self.num_workers):
            self.workers[worker_id].join()


class Worker(multiprocessing.Process):
    """Generic worker class implementation.

    Worker instance accepts (operation, payload) over work queue and
    depending upon requested operation starts a new thread to handle the work.
    """

    operations = namedtuple('WorkerOperations', (
        'HTTP_PROXY',
        'SHUTDOWN',
    ))(1, 2)

    def __init__(self, work_queue, config=None):
        super(Worker, self).__init__()
        self.work_queue = work_queue
        self.config = config

    def run(self):
        while True:
            try:
                op, payload = self.work_queue.get(True, 1)
                if op == Worker.operations.HTTP_PROXY:
                    proxy = HttpProxy(payload, config=self.config)
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


def set_open_file_limit(soft_limit):
    """Configure open file description soft limit on supported OS."""
    if os.name != 'nt':  # resource module not available on Windows OS
        curr_soft_limit, curr_hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if curr_soft_limit < soft_limit < curr_hard_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
            logger.debug('Open file descriptor soft limit set to %d' % soft_limit)


def init_parser():
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
                        help='Default: 8 KB. Maximum amount of data received from the '
                             'client in a single recv() operation. Bump this '
                             'value for faster uploads at the expense of '
                             'increased RAM.')
    parser.add_argument('--hostname', type=str, default=DEFAULT_IPV4_HOSTNAME,
                        help='Default: 127.0.0.1. Server IP address.')
    parser.add_argument('--ipv4', action='store_true', default=DEFAULT_IPV4,
                        help='Whether to listen on IPv4 address. '
                             'By default server only listens on IPv6.')
    parser.add_argument('--log-level', type=str, default=DEFAULT_LOG_LEVEL,
                        help='Valid options: DEBUG, INFO (default), WARNING, ERROR, CRITICAL. '
                             'Both upper and lowercase values are allowed.'
                             'You may also simply use the leading character e.g. --log-level d')
    parser.add_argument('--log-format', type=str, default=DEFAULT_LOG_FORMAT,
                        help='Log format for Python logger.')
    parser.add_argument('--open-file-limit', type=int, default=DEFAULT_OPEN_FILE_LIMIT,
                        help='Default: 1024. Maximum number of files (TCP connections) '
                             'that proxy.py can open concurrently.')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help='Default: 8899. Server port.')
    parser.add_argument('--pac-file', type=str, default=DEFAULT_PAC_FILE,
                        help='A file (Proxy Auto Configuration) or string to serve when '
                             'the server receives a direct file request.')
    parser.add_argument('--plugins', type=str, default=None, help='Comma separated plugins')
    parser.add_argument('--server-recvbuf-size', type=int, default=DEFAULT_SERVER_RECVBUF_SIZE,
                        help='Default: 8 KB. Maximum amount of data received from the '
                             'server in a single recv() operation. Bump this '
                             'value for faster downloads at the expense of '
                             'increased RAM.')
    parser.add_argument('--num-workers', type=int, default=DEFAULT_NUM_WORKERS,
                        help='Defaults to number of CPU cores.')
    return parser


def load_plugins(plugins):
    p = []
    plugins = plugins.split(',')
    for plugin in plugins:
        module_name, klass_name = plugin.rsplit('.', 1)
        module = importlib.import_module(module_name)
        klass = getattr(module, klass_name)
        logging.info('%s initialized' % klass.__name__)
        p.append(klass())
    return p


def main():
    if not PY3 and not UNDER_TEST:
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
    args = parser.parse_args(sys.argv[1:])

    logging.basicConfig(level=getattr(logging,
                                      {
                                          'D': 'DEBUG',
                                          'I': 'INFO',
                                          'W': 'WARNING',
                                          'E': 'ERROR',
                                          'C': 'CRITICAL'
                                      }[args.log_level.upper()[0]]),
                        format=args.log_format)
    plugins = load_plugins(args.plugins) if args.plugins else DEFAULT_PLUGINS

    try:
        set_open_file_limit(args.open_file_limit)

        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        server = MultiCoreRequestDispatcher(hostname=args.hostname,
                                            port=args.port,
                                            backlog=args.backlog,
                                            ipv4=args.ipv4,
                                            num_workers=args.num_workers,
                                            config=HttpProxyConfig(auth_code=auth_code,
                                                                   server_recvbuf_size=args.server_recvbuf_size,
                                                                   client_recvbuf_size=args.client_recvbuf_size,
                                                                   pac_file=args.pac_file,
                                                                   plugins=plugins))
        server.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
