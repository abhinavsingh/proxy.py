#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~

    HTTP Proxy Server in Python.

    :copyright: (c) 2013-2018 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import os
import sys
import errno
import base64
import socket
import select
import logging
import argparse
import datetime
import threading
from collections import namedtuple

if os.name != 'nt':
    import resource

VERSION = (0, 3)
__version__ = '.'.join(map(str, VERSION[0:2]))
__description__ = 'HTTP Proxy Server in Python'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__download_url__ = '%s/archive/master.zip' % __homepage__
__license__ = 'BSD'

logger = logging.getLogger(__name__)

PY3 = sys.version_info[0] == 3

if PY3:    # pragma: no cover
    text_type = str
    binary_type = bytes
    from urllib import parse as urlparse
else:   # pragma: no cover
    text_type = unicode
    binary_type = str
    import urlparse


def text_(s, encoding='utf-8', errors='strict'):    # pragma: no cover
    """Utility to ensure text-like usability.

    If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    return s


def bytes_(s, encoding='utf-8', errors='strict'):   # pragma: no cover
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

BAD_GATEWAY_RESPONSE_PKT = CRLF.join([
    b'HTTP/1.1 502 Bad Gateway',
    PROXY_AGENT_HEADER,
    b'Content-Length: 11',
    b'Connection: close',
    CRLF
]) + b'Bad Gateway'

PROXY_AUTHENTICATION_REQUIRED_RESPONSE_PKT = CRLF.join([
    b'HTTP/1.1 407 Proxy Authentication Required',
    PROXY_AGENT_HEADER,
    b'Content-Length: 29',
    b'Connection: close',
    CRLF
]) + b'Proxy Authentication Required'


class ChunkParser(object):
    """HTTP chunked encoding response parser."""

    states = namedtuple('ChunkParserStates', (
        'WAITING_FOR_SIZE',
        'WAITING_FOR_DATA',
        'COMPLETE'
    ))(1, 2, 3)

    def __init__(self):
        self.state = ChunkParser.states.WAITING_FOR_SIZE
        self.body = b''     # Parsed chunks
        self.chunk = b''    # Partial chunk received
        self.size = None    # Expected size of next following chunk

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
            if not line:    # CRLF not received
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
            elif b'transfer-encoding' in self.headers and self.headers[b'transfer-encoding'][1].lower() == b'chunked':
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

        if self.state == HttpParser.states.HEADERS_COMPLETE and \
                self.type == HttpParser.types.REQUEST_PARSER and \
                not self.method == b'POST' and \
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
                req += self.build_header(self.headers[k][0], self.headers[k][1])

        if not add_headers:
            add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1])

        req += CRLF
        if self.body:
            req += self.body

        return req

    @staticmethod
    def build_header(k, v):
        return k + b': ' + v + CRLF

    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1:
            return False, data
        line = data[:pos]
        data = data[pos + len(CRLF):]
        return line, data


class Connection(object):
    """TCP server/client connection abstraction."""

    def __init__(self, what):
        self.conn = None
        self.buffer = b''
        self.closed = False
        self.what = what  # server or client

    def send(self, data):
        # TODO: Gracefully handle BrokenPipeError exceptions
        return self.conn.send(data)

    def recv(self, bufsiz=8192):
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


class Server(Connection):
    """Establish connection to destination server."""

    def __init__(self, host, port):
        super(Server, self).__init__(b'server')
        self.addr = (host, int(port))

    def __del__(self):
        if self.conn:
            self.close()

    def connect(self):
        self.conn = socket.create_connection((self.addr[0], self.addr[1]))


class Client(Connection):
    """Accepted client connection."""

    def __init__(self, conn, addr):
        super(Client, self).__init__(b'client')
        self.conn = conn
        self.addr = addr


class ProxyError(Exception):
    pass


class ProxyConnectionFailed(ProxyError):

    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason

    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)


class ProxyAuthenticationFailed(ProxyError):
    pass


class Proxy(threading.Thread):
    """HTTP proxy implementation.

    Accepts `Client` connection object and act as a proxy between client and server.
    """

    def __init__(self, client, auth_code=None, server_recvbuf_size=8192, client_recvbuf_size=8192):
        super(Proxy, self).__init__()

        self.start_time = self._now()
        self.last_activity = self.start_time

        self.auth_code = auth_code
        self.client = client
        self.client_recvbuf_size = client_recvbuf_size
        self.server = None
        self.server_recvbuf_size = server_recvbuf_size

        self.request = HttpParser(HttpParser.types.REQUEST_PARSER)
        self.response = HttpParser(HttpParser.types.RESPONSE_PARSER)

    @staticmethod
    def _now():
        return datetime.datetime.utcnow()

    def _inactive_for(self):
        return (self._now() - self.last_activity).seconds

    def _is_inactive(self):
        return self._inactive_for() > 30

    def _process_request(self, data):
        # once we have connection to the server
        # we don't parse the http request packets
        # any further, instead just pipe incoming
        # data from client to server
        if self.server and not self.server.closed:
            self.server.queue(data)
            return

        # parse http request
        self.request.parse(data)

        # once http request parser has reached the state complete
        # we attempt to establish connection to destination server
        if self.request.state == HttpParser.states.COMPLETE:
            logger.debug('request parser is in state complete')

            if self.auth_code:
                if b'proxy-authorization' not in self.request.headers or \
                        self.request.headers[b'proxy-authorization'][1] != self.auth_code:
                    raise ProxyAuthenticationFailed()

            if self.request.method == b'CONNECT':
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80
            else:
                raise Exception('Invalid request\n%s' % self.request.raw)

            self.server = Server(host, port)
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

    def _process_response(self, data):
        # parse incoming response packet
        # only for non-https requests
        if not self.request.method == b'CONNECT':
            self.response.parse(data)

        # queue data for client
        self.client.queue(data)

    def _access_log(self):
        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b'CONNECT':
            logger.info(
                '%s:%s - %s %s:%s' % (self.client.addr[0], self.client.addr[1], self.request.method, host, port))
        elif self.request.method:
            logger.info('%s:%s - %s %s:%s%s - %s %s - %s bytes' % (
                self.client.addr[0], self.client.addr[1], self.request.method, host, port, self.request.build_url(),
                self.response.code, self.response.reason, len(self.response.raw)))

    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.conn], [], []
        if self.client.has_buffer():
            wlist.append(self.client.conn)
        if self.server and not self.server.closed:
            rlist.append(self.server.conn)
        if self.server and not self.server.closed and self.server.has_buffer():
            wlist.append(self.server.conn)
        return rlist, wlist, xlist

    def _process_wlist(self, w):
        if self.client.conn in w:
            logger.debug('client is ready for writes, flushing client buffer')
            self.client.flush()

        if self.server and not self.server.closed and self.server.conn in w:
            logger.debug('server is ready for writes, flushing server buffer')
            self.server.flush()

    def _process_rlist(self, r):
        """Returns True if connection to client must be closed."""
        if self.client.conn in r:
            logger.debug('client is ready for reads, reading')
            data = self.client.recv(self.client_recvbuf_size)
            self.last_activity = self._now()

            if not data:
                logger.debug('client closed connection, breaking')
                return True

            try:
                self._process_request(data)
            except (ProxyAuthenticationFailed, ProxyConnectionFailed) as e:
                logger.exception(e)
                self.client.queue(Proxy._get_response_pkt_by_exception(e))
                self.client.flush()
                return True

        if self.server and not self.server.closed and self.server.conn in r:
            logger.debug('server is ready for reads, reading')
            data = self.server.recv(self.server_recvbuf_size)
            self.last_activity = self._now()

            if not data:
                logger.debug('server closed connection')
                self.server.close()
            else:
                self._process_response(data)

        return False

    def _process(self):
        while True:
            rlist, wlist, xlist = self._get_waitable_lists()
            r, w, x = select.select(rlist, wlist, xlist, 1)

            self._process_wlist(w)
            if self._process_rlist(r):
                break

            if self.client.buffer_size() == 0:
                if self.response.state == HttpParser.states.COMPLETE:
                    logger.debug('client buffer is empty and response state is complete, breaking')
                    break

                if self._is_inactive():
                    logger.debug('client buffer is empty and maximum inactivity has reached, breaking')
                    break

    @staticmethod
    def _get_response_pkt_by_exception(e):
        if e.__class__.__name__ == 'ProxyAuthenticationFailed':
            return PROXY_AUTHENTICATION_REQUIRED_RESPONSE_PKT
        if e.__class__.__name__ == 'ProxyConnectionFailed':
            return BAD_GATEWAY_RESPONSE_PKT

    def run(self):
        logger.debug('Proxying connection %r' % self.client.conn)
        try:
            self._process()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.client.conn, e))
        finally:
            logger.debug(
                'closing client connection with pending client buffer size %d bytes' % self.client.buffer_size())
            self.client.close()
            if self.server:
                logger.debug(
                    'closed client connection with pending server buffer size %d bytes' % self.server.buffer_size())
            self._access_log()
            logger.debug('Closing proxy for connection %r at address %r' % (self.client.conn, self.client.addr))


class TCP(object):
    """TCP server implementation.

    Subclass MUST implement `handle` method. It accepts an instance of accepted `Client` connection.
    """

    def __init__(self, hostname='127.0.0.1', port=8899, backlog=100):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog
        self.socket = None

    def handle(self, client):
        raise NotImplementedError()

    def run(self):
        try:
            logger.info('Starting server on port %d' % self.port)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(self.backlog)
            while True:
                conn, addr = self.socket.accept()
                client = Client(conn, addr)
                self.handle(client)
        except Exception as e:
            logger.exception('Exception while running the server %r' % e)
        finally:
            logger.info('Closing server socket')
            self.socket.close()


class HTTP(TCP):
    """HTTP proxy server implementation.

    Spawns new process to proxy accepted client connection.
    """

    def __init__(self, hostname='127.0.0.1', port=8899, backlog=100,
                 auth_code=None, server_recvbuf_size=8192, client_recvbuf_size=8192):
        super(HTTP, self).__init__(hostname, port, backlog)
        self.auth_code = auth_code
        self.client_recvbuf_size = client_recvbuf_size
        self.server_recvbuf_size = server_recvbuf_size

    def handle(self, client):
        proxy = Proxy(client,
                      auth_code=self.auth_code,
                      server_recvbuf_size=self.server_recvbuf_size,
                      client_recvbuf_size=self.client_recvbuf_size)
        proxy.daemon = True
        proxy.start()


def set_open_file_limit(soft_limit):
    """Configure open file description soft limit on supported OS."""
    if os.name != 'nt':  # resource module not available on Windows OS
        curr_soft_limit, curr_hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if curr_soft_limit < soft_limit < curr_hard_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, curr_hard_limit))
            logger.info('Open file descriptor soft limit set to %d' % soft_limit)


def main():
    parser = argparse.ArgumentParser(
        description='proxy.py v%s' % __version__,
        epilog='Having difficulty using proxy.py? Report at: %s/issues/new' % __homepage__
    )

    parser.add_argument('--hostname', default='127.0.0.1', help='Default: 127.0.0.1')
    parser.add_argument('--port', default='8899', help='Default: 8899')
    parser.add_argument('--backlog', default='100', help='Default: 100. '
                                                         'Maximum number of pending connections to proxy server')
    parser.add_argument('--basic-auth', default=None, help='Default: No authentication. '
                                                           'Specify colon separated user:password '
                                                           'to enable basic authentication.')
    parser.add_argument('--server-recvbuf-size', default='8192', help='Default: 8 KB. '
                                                                      'Maximum amount of data received from the '
                                                                      'server in a single recv() operation. Bump this '
                                                                      'value for faster downloads at the expense of '
                                                                      'increased RAM.')
    parser.add_argument('--client-recvbuf-size', default='8192', help='Default: 8 KB. '
                                                                      'Maximum amount of data received from the '
                                                                      'client in a single recv() operation. Bump this '
                                                                      'value for faster uploads at the expense of '
                                                                      'increased RAM.')
    parser.add_argument('--open-file-limit', default='1024', help='Default: 1024. '
                                                                  'Maximum number of files (TCP connections) '
                                                                  'that proxy.py can open concurrently.')
    parser.add_argument('--log-level', default='INFO', help='DEBUG, INFO (default), WARNING, ERROR, CRITICAL')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level),
                        format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')

    try:
        set_open_file_limit(int(args.open_file_limit))

        auth_code = None
        if args.basic_auth:
            auth_code = b'Basic %s' % base64.b64encode(bytes_(args.basic_auth))

        proxy = HTTP(hostname=args.hostname,
                     port=int(args.port),
                     backlog=int(args.backlog),
                     auth_code=auth_code,
                     server_recvbuf_size=int(args.server_recvbuf_size),
                     client_recvbuf_size=int(args.client_recvbuf_size))
        proxy.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
