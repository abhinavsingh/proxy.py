#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    
    HTTP Proxy Server in Python.
    
    :copyright: (c) 2013 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
VERSION = (0, 1)
__version__ = '.'.join(map(str, VERSION[0:2]))
__description__ = 'HTTP Proxy Server in Python'
__author__ = 'Abhinav Singh'
__author_email__ = 'mailsforabhinav@gmail.com'
__homepage__ = 'https://github.com/abhinavsingh/proxy.py'
__license__ = 'BSD'

import multiprocessing
import datetime
import urlparse
import argparse
import logging
import socket
import select

logger = logging.getLogger('proxy.py')

CRLF, COLON, SP = '\r\n', ':', ' '

HTTP_REQUEST_PARSER = 1
HTTP_RESPONSE_PARSER = 2

HTTP_PARSER_STATE_INITIALIZED = 1
HTTP_PARSER_STATE_LINE_RCVD = 2
HTTP_PARSER_STATE_RCVING_HEADERS = 3
HTTP_PARSER_STATE_HEADERS_COMPLETE = 4
HTTP_PARSER_STATE_RCVING_BODY = 5
HTTP_PARSER_STATE_COMPLETE = 6

CHUNK_PARSER_STATE_WAITING_FOR_SIZE = 1
CHUNK_PARSER_STATE_WAITING_FOR_DATA = 2
CHUNK_PARSER_STATE_COMPLETE = 3

class ChunkParser(object):
    """HTTP chunked encoding response parser."""
    
    def __init__(self):
        self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
        self.body = ''
        self.chunk = ''
        self.size = None
    
    def parse(self, data):
        more = True if len(data) > 0 else False
        while more: more, data = self.process(data)
    
    def process(self, data):
        if self.state == CHUNK_PARSER_STATE_WAITING_FOR_SIZE:
            line, data = HttpParser.split(data)
            self.size = int(line, 16)
            self.state = CHUNK_PARSER_STATE_WAITING_FOR_DATA
        elif self.state == CHUNK_PARSER_STATE_WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = CHUNK_PARSER_STATE_COMPLETE
                else:
                    self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
                self.chunk = ''
                self.size = None
        return len(data) > 0, data

class HttpParser(object):
    """HTTP request/response parser."""
    
    def __init__(self, type=None):
        self.state = HTTP_PARSER_STATE_INITIALIZED
        self.type = type if type else HTTP_REQUEST_PARSER
        
        self.raw = ''
        self.buffer = ''
        
        self.headers = dict()
        self.body = None
        
        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None
        
        self.chunker = None
    
    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = ''
        
        more = True if len(data) > 0 else False
        while more: more, data = self.process(data)
        self.buffer = data
    
    def process(self, data):
        if self.state >= HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        (self.method == "POST" or self.type == HTTP_RESPONSE_PARSER):
            if not self.body:
                self.body = ''
            
            if 'content-length' in self.headers:
                self.state = HTTP_PARSER_STATE_RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers['content-length'][1]):
                    self.state = HTTP_PARSER_STATE_COMPLETE
            elif 'transfer-encoding' in self.headers and self.headers['transfer-encoding'][1].lower() == 'chunked':
                if not self.chunker:
                    self.chunker = ChunkParser()
                self.chunker.parse(data)
                if self.chunker.state == CHUNK_PARSER_STATE_COMPLETE:
                    self.body = self.chunker.body
                    self.state = HTTP_PARSER_STATE_COMPLETE
            
            return False, ''
        
        line, data = HttpParser.split(data)
        if line == False: return line, data
        
        if self.state < HTTP_PARSER_STATE_LINE_RCVD:
            self.process_line(line)
        elif self.state < HTTP_PARSER_STATE_HEADERS_COMPLETE:
            self.process_header(line)
        
        if self.state == HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        self.type == HTTP_REQUEST_PARSER and \
        not self.method == "POST" and \
        self.raw.endswith(CRLF*2):
                self.state = HTTP_PARSER_STATE_COMPLETE
        
        return len(data) > 0, data
    
    def process_line(self, data):
        line = data.split(SP)
        if self.type == HTTP_REQUEST_PARSER:
            self.method = line[0].upper()
            self.url = urlparse.urlsplit(line[1])
            self.version = line[2]
        else:
            self.version = line[0]
            self.code = line[1]
            self.reason = ' '.join(line[2:])
        self.state = HTTP_PARSER_STATE_LINE_RCVD
    
    def process_header(self, data):
        if len(data) == 0:
            if self.state == HTTP_PARSER_STATE_RCVING_HEADERS:
                self.state = HTTP_PARSER_STATE_HEADERS_COMPLETE
            elif self.state == HTTP_PARSER_STATE_LINE_RCVD:
                self.state = HTTP_PARSER_STATE_RCVING_HEADERS
        else:
            self.state = HTTP_PARSER_STATE_RCVING_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)
    
    def build_url(self):
        if not self.url:
            return '/None'
        
        url = self.url.path
        if url == '': url = '/'
        if not self.url.query == '': url += '?' + self.url.query
        if not self.url.fragment == '': url += '#' + self.url.fragment
        return url
    
    def build_header(self, k, v):
        return '%s: %s%s' % (k, v, CRLF)
    
    def build(self, del_headers=None, add_headers=None):
        req = '%s %s %s' % (self.method, self.build_url(), self.version)
        req += CRLF
        
        if not del_headers: del_headers = []
        for k in self.headers:
            if not k in del_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1])
        
        if not add_headers: add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1])
        
        req += CRLF
        if self.body:
            req += self.body
        
        return req
    
    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1: return False, data
        line = data[:pos]
        data = data[pos+len(CRLF):]
        return line, data

class Server(object):
    """Established connection to destination server for proxying."""
    
    def __init__(self, host, port):
        self.addr = (host, int(port))
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.addr[0], self.addr[1]))
    
    def send(self, data):
        return self.conn.send(data)
    
    def recv(self, bytes):
        return self.conn.recv(bytes)

class Client(object):
    """Accepted client connection."""
    
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
    
    def send(self, data):
        return self.conn.send(data)
    
    def recv(self, bytes):
        return self.conn.recv(bytes)

class ProxyError(Exception):
    pass

class ProxyConnectionFailed(ProxyError):
    pass

class Proxy(multiprocessing.Process):
    """HTTP proxy implementation.
    
    Accepts connection object and act as a proxy between client and server.
    """
    
    def __init__(self, client):
        super(Proxy, self).__init__()
        
        self.start_time = self._now()
        self.last_activity = self.start_time
        
        self.client = client
        self.server = None
        
        self.request = HttpParser()
        self.response = HttpParser(HTTP_RESPONSE_PARSER)
        
        self.buffer = dict()
        self.buffer['client'] = ''
        self.buffer['server'] = ''
        
        self.host = None
        self.port = None
    
    def _now(self):
        return datetime.datetime.utcnow()
    
    def _inactive_for(self):
        return (self._now() - self.last_activity).seconds
    
    def _is_inactive(self):
        return self._inactive_for() > 30
    
    def _recv(self, what):
        try:
            data = getattr(self, what).recv(8192)
            self.last_activity = self._now()
            if len(data) == 0:
                logger.debug('recvd 0 bytes from %s' % what)
                return None
            logger.debug('rcvd %d bytes from %s' % (len(data), what))
            return data
        except Exception as e:
            logger.exception('Exception while receiving from connection %r with reason %r' % (getattr(self, what), e))
            return None
    
    def _recv_from_client(self):
        return self._recv('client')
    
    def _recv_from_server(self):
        return self._recv('server')
    
    def _send(self, what, data):
        self.buffer[what] += data
    
    def _send_to_client(self, data):
        self._send('client', data)
    
    def _send_to_server(self, data):
        self._send('server', data)
    
    def _flush(self, what):
        sent = getattr(self, what).send(self.buffer[what])
        logger.debug('flushed %d bytes to %s' % (sent, what))
        self.buffer[what] = self.buffer[what][sent:]
    
    def _flush_client_buffer(self):
        self._flush('client')
    
    def _flush_server_buffer(self):
        self._flush('server')
    
    def _server_host_port(self):
        if not self.host and not self.port:
            if self.request.method == "CONNECT":
                self.host, self.port = self.request.url.path.split(':')
            elif self.request.url:
                self.host, self.port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80
        return self.host, self.port
    
    def _connect_to_server(self):
        host, port = self._server_host_port()
        logger.debug('connecting to server %s:%s' % (host, port))
        self.server = Server(host, port)
        logger.debug('connected to server %s:%s' % (host, port))
    
    def _process_request(self, data):
        if self.server:
            self._send_to_server(data)
            return
        
        self.request.parse(data)
        
        if self.request.state == HTTP_PARSER_STATE_COMPLETE:
            logger.debug('request parser is in state complete')
            
            try:
                self._connect_to_server()
            except Exception, e:
                raise ProxyConnectionFailed("%r" % e)
            
            if self.request.method == "CONNECT":
                self._send_to_client(CRLF.join([
                    'HTTP/1.1 200 Connection established',
                    'Proxy-agent: BroPro',
                    CRLF
                ]))
            else:
                self._send_to_server(self.request.build(
                    del_headers=['proxy-connection', 'connection', 'keep-alive'], 
                    add_headers=[('Connection', 'Close')]
                ))
    
    def _process_response(self, data):
        if not self.request.method == "CONNECT":
            self.response.parse(data)
        self._send_to_client(data)
    
    def _access_log(self):
        host, port = self._server_host_port()
        if self.request.method == "CONNECT":
            logger.info("%s:%s - %s %s:%s" % (self.client.addr[0], self.client.addr[1], self.request.method, host, port))
        else:
            logger.info("%s:%s - %s %s:%s%s - %s %s - %s bytes" % (self.client.addr[0], self.client.addr[1], self.request.method, host, port, self.request.build_url(), self.response.code, self.response.reason, len(self.response.raw)))
    
    def run(self):
        logger.debug('Proxying connection %r at address %r' % (self.client.conn, self.client.addr))
        try:
            while True:
                rlist, wlist, xlist = [self.client.conn], [], []
                logger.debug('*** watching client for read ready')
                
                if len(self.buffer['client']) > 0:
                    logger.debug('pending client buffer found, watching client for write ready')
                    wlist.append(self.client.conn)
                
                if self.server:
                    logger.debug('connection to server exists, watching server for read ready')
                    rlist.append(self.server.conn)
                
                if self.server and len(self.buffer['server']) > 0:
                    logger.debug('connection to server exists and pending server buffer found, watching server for write ready')
                    wlist.append(self.server.conn)
                
                r, w, x = select.select(rlist, wlist, xlist, 1)
                
                if self.client.conn in w:
                    logger.debug('client is ready for writes, flushing client buffer')
                    self._flush_client_buffer()
                
                if self.server and self.server.conn in w:
                    logger.debug('server is ready for writes, flushing server buffer')
                    self._flush_server_buffer()
                
                if self.client.conn in r:
                    logger.debug('client is ready for reads, reading')
                    data = self._recv_from_client()
                    if not data:
                        logger.debug('client closed connection, breaking')
                        break
                    self._process_request(data)
                
                if self.server and self.server.conn in r:
                    logger.debug('server is ready for reads, reading')
                    data = self._recv_from_server()
                    if not data:
                        logger.debug('server closed connection')
                        self.server.conn.close()
                        self.server = None
                    else:
                        self._process_response(data)
                
                if len(self.buffer['client']) == 0:
                    if self.response.state == HTTP_PARSER_STATE_COMPLETE:
                        logger.debug('client buffer is empty and response state is complete, breaking')
                        break
                    
                    if self._is_inactive():
                        logger.debug('client buffer is empty and maximum inactivity has reached, breaking')
                        break
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.client.conn, e))
        finally:
            logger.debug("closing client connection with client pending buffer size %d bytes, server pending buffer size %d bytes" % (len(self.buffer['client']), len(self.buffer['server'])))
            self.client.conn.close()
            self._access_log()
            logger.debug('Closing proxy for connection %r at address %r' % (self.client.conn, self.client.addr))

class Http(object):
    """HTTP server implementation.
    
    Listens on configured (host, port) and spawns a new process
    for handling every accepted HTTP connection. Spawned process
    takes care of proxying the HTTP request.
    """
    
    def __init__(self, hostname='127.0.0.1', port=8899, backlog=100):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog
    
    def run(self):
        try:
            logger.info('Starting proxy server on port %d' % self.port)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(self.backlog)
            while True:
                conn, addr = self.socket.accept()
                logger.debug('Accepted connection %r at address %r' % (conn, addr))
                client = Client(conn, addr)
                proc = Proxy(client)
                proc.daemon = True
                proc.start()
                logger.debug('Started process %r to handle connection %r' % (proc, conn))
        except Exception as e:
            logger.exception('Exception while running the server %r' % e)
        finally:
            logger.info('Closing server socket')
            self.socket.close()

def main():
    parser = argparse.ArgumentParser(
        description='proxy.py v%s' % __version__,
        epilog='Having difficulty using proxy.py? Report at: %s/issues/new' % __homepage__
    )
    parser.add_argument('--hostname', default='127.0.0.1', help='Default: 127.0.0.1')
    parser.add_argument('--port', default='8899', help='Default: 8899')
    parser.add_argument('--log-level', default='INFO', help='DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = parser.parse_args()
    
    hostname = args.hostname
    port = int(args.port)
    logging.basicConfig(level=getattr(logging, args.log_level), format='%(levelname)s - %(asctime)s - %(lineno)d - %(message)s')
    
    try:
        http = Http(hostname, port)
        http.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
