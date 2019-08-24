# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~

    HTTP, HTTPS, HTTP2 and WebSockets Proxy Server in Python.

    :copyright: (c) 2013-2020 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import base64
import logging
import multiprocessing
import os
import socket
import time
import unittest
from contextlib import closing
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest import mock

import proxy

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')


def get_available_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return port


@unittest.skipIf(os.getenv('TESTING_ON_TRAVIS', 0), 'Opening sockets not allowed on Travis')
class TestTcpServer(unittest.TestCase):
    ipv4_port = None
    ipv6_port = None
    ipv4_server = None
    ipv6_server = None
    ipv4_thread = None
    ipv6_thread = None

    class _TestTcpServer(proxy.TcpServer):

        def handle(self, client):
            data = client.recv(proxy.DEFAULT_BUFFER_SIZE)
            assert data == b'HELLO'
            client.conn.sendall(b'WORLD')
            client.close()

    @classmethod
    def setUpClass(cls):
        cls.ipv4_port = get_available_port()
        cls.ipv6_port = get_available_port()
        cls.ipv4_server = TestTcpServer._TestTcpServer(port=cls.ipv4_port, ipv4=True)
        cls.ipv6_server = TestTcpServer._TestTcpServer(hostname=proxy.DEFAULT_IPV6_HOSTNAME, port=cls.ipv6_port,
                                                       ipv4=False)
        cls.ipv4_thread = Thread(target=cls.ipv4_server.run)
        cls.ipv6_thread = Thread(target=cls.ipv6_server.run)
        cls.ipv4_thread.setDaemon(True)
        cls.ipv6_thread.setDaemon(True)
        cls.ipv4_thread.start()
        cls.ipv6_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.ipv4_server.stop()
        cls.ipv4_thread.join()

    def baseTestCase(self, ipv4=True):
        while True:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET if ipv4 else socket.AF_INET6, socket.SOCK_STREAM, 0)
                sock.connect((proxy.DEFAULT_IPV4_HOSTNAME if ipv4 else proxy.DEFAULT_IPV6_HOSTNAME,
                              self.ipv4_port if ipv4 else self.ipv6_port))
                sock.sendall(b'HELLO')
                data = sock.recv(proxy.DEFAULT_BUFFER_SIZE)
                self.assertEqual(data, b'WORLD')
                break
            except ConnectionRefusedError:
                time.sleep(0.1)
            finally:
                sock.close()

    def testIpv4ClientConnection(self):
        self.baseTestCase()

    def testIpv6ClientConnection(self):
        self.baseTestCase(ipv4=False)


class MockHttpProxy(object):

    def __init__(self, client, **kwargs):
        self.client = client
        self.kwargs = kwargs

    def setDaemon(self, _val):
        pass

    def start(self):
        self.client.conn.sendall(proxy.CRLF.join([b'HTTP/1.1 200 OK', proxy.CRLF]))
        self.client.conn.close()


def mock_tcp_proxy_side_effect(client, **kwargs):
    return MockHttpProxy(client, **kwargs)


@unittest.skipIf(os.getenv('TESTING_ON_TRAVIS', 0), 'Opening sockets not allowed on Travis')
class TestMultiCoreRequestDispatcher(unittest.TestCase):
    tcp_port = None
    tcp_server = None
    tcp_thread = None

    @mock.patch.object(proxy, 'HttpProtocolHandler', side_effect=mock_tcp_proxy_side_effect)
    def testHttpProxyConnection(self, mock_tcp_proxy):
        try:
            self.tcp_port = get_available_port()
            self.tcp_server = proxy.MultiCoreRequestDispatcher(hostname=proxy.DEFAULT_IPV4_HOSTNAME, port=self.tcp_port,
                                                               ipv4=True, num_workers=1)
            self.tcp_thread = Thread(target=self.tcp_server.run)
            self.tcp_thread.setDaemon(True)
            self.tcp_thread.start()

            while True:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                    sock.connect((proxy.DEFAULT_IPV4_HOSTNAME, self.tcp_port))
                    sock.send(proxy.CRLF.join([
                        b'GET http://httpbin.org/get HTTP/1.1',
                        b'Host: httpbin.org',
                        proxy.CRLF
                    ]))
                    data = sock.recv(proxy.DEFAULT_BUFFER_SIZE)
                    self.assertEqual(data, proxy.CRLF.join([b'HTTP/1.1 200 OK', proxy.CRLF]))
                    self.tcp_server.shutdown()  # explicit early call worker shutdown to avoid resource leak warnings
                    break
                except ConnectionRefusedError:
                    time.sleep(0.1)
                finally:
                    sock.close()
        finally:
            self.tcp_server.stop()
            self.tcp_thread.join()


class TestChunkParser(unittest.TestCase):

    def setUp(self):
        self.parser = proxy.ChunkParser()

    def test_chunk_parse_basic(self):
        self.parser.parse(b''.join([
            b'4\r\n',
            b'Wiki\r\n',
            b'5\r\n',
            b'pedia\r\n',
            b'E\r\n',
            b' in\r\n\r\nchunks.\r\n',
            b'0\r\n',
            b'\r\n'
        ]))
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.COMPLETE)

    def test_chunk_parse_issue_27(self):
        """Case when data ends with the chunk size but without ending CRLF."""
        self.parser.parse(b'3')
        self.assertEqual(self.parser.chunk, b'3')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 3)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_DATA)
        self.parser.parse(b'abc')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'4\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 4)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_DATA)
        self.parser.parse(b'defg\r\n0')
        self.assertEqual(self.parser.chunk, b'0')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.COMPLETE)


class TestHttpParser(unittest.TestCase):

    def setUp(self):
        self.parser = proxy.HttpParser(proxy.HttpParser.types.REQUEST_PARSER)

    def test_build_header(self):
        self.assertEqual(proxy.HttpParser.build_header(b'key', b'value'), b'key: value')

    def test_split(self):
        self.assertEqual(proxy.HttpParser.split(b'CONNECT python.org:443 HTTP/1.0\r\n\r\n'),
                         (b'CONNECT python.org:443 HTTP/1.0', b'\r\n'))

    def test_split_false_line(self):
        self.assertEqual(proxy.HttpParser.split(b'CONNECT python.org:443 HTTP/1.0'),
                         (False, b'CONNECT python.org:443 HTTP/1.0'))

    def test_get_full_parse(self):
        raw = proxy.CRLF.join([
            b'GET %s HTTP/1.1',
            b'Host: %s',
            proxy.CRLF
        ])
        self.parser.parse(raw % (b'https://example.com/path/dir/?a=b&c=d#p=q', b'example.com'))
        self.assertEqual(self.parser.build_url(), b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertDictContainsSubset({b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.assertEqual(raw % (b'/path/dir/?a=b&c=d#p=q', b'example.com'),
                         self.parser.build(del_headers=[b'host'], add_headers=[(b'Host', b'example.com')]))

    def test_build_url_none(self):
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self):
        self.parser.parse(b'GET http://localhost HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.INITIALIZED)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)

    def test_get_partial_parse1(self):
        self.parser.parse(proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1'
        ]))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.INITIALIZED)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)

        self.parser.parse(b'Host: localhost:8080')
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)

        self.parser.parse(proxy.CRLF * 2)
        self.assertDictContainsSubset({b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_get_partial_parse2(self):
        self.parser.parse(proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
            b'Host: '
        ]))
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)

        self.parser.parse(b'localhost:8080' + proxy.CRLF)
        self.assertDictContainsSubset({b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + proxy.CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset({b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_post_full_parse(self):
        raw = proxy.CRLF.join([
            b'POST %s HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded' + proxy.CRLF,
            b'a=b&c=d'
        ])
        self.parser.parse(raw % b'http://localhost')
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertDictContainsSubset({b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')},
                                      self.parser.headers)
        self.assertDictContainsSubset({b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def test_post_partial_parse(self):
        self.parser.parse(proxy.CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded'
        ]))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_BODY)
        self.assertEqual(self.parser.body, b'a=b')
        self.assertEqual(self.parser.buffer, b'')

        self.parser.parse(b'&c=d')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')

    def test_connect_request_without_host_header_request_parse(self):
        """Case where clients can send CONNECT request without a Host header field.

        Example:
            1. pip3 --proxy http://localhost:8899 install <package name>
               Uses HTTP/1.0, Host header missing with CONNECT requests
            2. Android Emulator
               Uses HTTP/1.1, Host header missing with CONNECT requests

        See https://github.com/abhinavsingh/proxy.py/issues/5 for details.
        """
        self.parser.parse(b'CONNECT pypi.org:443 HTTP/1.0\r\n\r\n')
        self.assertEqual(self.parser.method, b'CONNECT')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_request_parse_without_content_length(self):
        """Case when incoming request doesn't contain a content-length header.

        From http://w3-org.9356.n7.nabble.com/POST-with-empty-body-td103965.html
        'A POST with no content-length and no body is equivalent to a POST with Content-Length: 0
        and nothing following, as could perfectly happen when you upload an empty file for instance.'

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.
        """
        self.parser.parse(proxy.CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Type: application/x-www-form-urlencoded',
            proxy.CRLF
        ]))
        self.assertEqual(self.parser.method, b'POST')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_response_parse_without_content_length(self):
        """Case when server response doesn't contain a content-length header for non-chunk response types.

        HttpParser by itself has no way to know if more data should be expected.
        In example below, parser reaches state HttpParser.states.HEADERS_COMPLETE
        and it is responsibility of callee to change state to HttpParser.states.COMPLETE
        when server stream closes.

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.
        """
        self.parser.type = proxy.HttpParser.types.RESPONSE_PARSER
        self.parser.parse(b'HTTP/1.0 200 OK' + proxy.CRLF)
        self.assertEqual(self.parser.code, b'200')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)
        self.parser.parse(proxy.CRLF.join([
            b'Server: BaseHTTP/0.3 Python/2.7.10',
            b'Date: Thu, 13 Dec 2018 16:24:09 GMT',
            proxy.CRLF
        ]))
        self.assertEqual(self.parser.state, proxy.HttpParser.states.HEADERS_COMPLETE)

    def test_response_parse(self):
        self.parser.type = proxy.HttpParser.types.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 301 Moved Permanently\r\n',
            b'Location: http://www.google.com/\r\n',
            b'Content-Type: text/html; charset=UTF-8\r\n',
            b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            b'Cache-Control: public, max-age=2592000\r\n',
            b'Server: gws\r\n',
            b'Content-Length: 219\r\n',
            b'X-XSS-Protection: 1; mode=block\r\n',
            b'X-Frame-Options: SAMEORIGIN\r\n\r\n',
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>',
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n'
        ]))
        self.assertEqual(self.parser.code, b'301')
        self.assertEqual(self.parser.reason, b'Moved Permanently')
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.body,
                         b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
                         b'<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
                         b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset({b'content-length': (b'Content-Length', b'219')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_response_partial_parse(self):
        self.parser.type = proxy.HttpParser.types.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 301 Moved Permanently\r\n',
            b'Location: http://www.google.com/\r\n',
            b'Content-Type: text/html; charset=UTF-8\r\n',
            b'Date: Wed, 22 May 2013 14:07:29 GMT\r\n',
            b'Expires: Fri, 21 Jun 2013 14:07:29 GMT\r\n',
            b'Cache-Control: public, max-age=2592000\r\n',
            b'Server: gws\r\n',
            b'Content-Length: 219\r\n',
            b'X-XSS-Protection: 1; mode=block\r\n',
            b'X-Frame-Options: SAMEORIGIN\r\n'
        ]))
        self.assertDictContainsSubset({b'x-frame-options': (b'X-Frame-Options', b'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.RCVING_BODY)
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_chunked_response_parse(self):
        self.parser.type = proxy.HttpParser.types.RESPONSE_PARSER
        self.parser.parse(b''.join([
            b'HTTP/1.1 200 OK\r\n',
            b'Content-Type: application/json\r\n',
            b'Date: Wed, 22 May 2013 15:08:15 GMT\r\n',
            b'Server: gunicorn/0.16.1\r\n',
            b'transfer-encoding: chunked\r\n',
            b'Connection: keep-alive\r\n\r\n',
            b'4\r\n',
            b'Wiki\r\n',
            b'5\r\n',
            b'pedia\r\n',
            b'E\r\n',
            b' in\r\n\r\nchunks.\r\n',
            b'0\r\n',
            b'\r\n'
        ]))
        self.assertEqual(self.parser.body, b'Wikipedia in\r\n\r\nchunks.')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)


class MockTcpConnection(object):

    def __init__(self, b=b''):
        self.buffer = b

    def recv(self, b=8192):
        data = self.buffer[:b]
        self.buffer = self.buffer[b:]
        return data

    def send(self, data):
        return len(data)

    def queue(self, data):
        self.buffer += data


class HTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        # TODO(abhinavsingh): Proxy should work just fine even without content-length header
        self.send_header('content-length', 2)
        self.end_headers()
        self.wfile.write(b'OK')


class TestProxy(unittest.TestCase):
    http_server = None
    http_server_port = None
    http_server_thread = None
    config = None

    @classmethod
    def setUpClass(cls):
        cls.http_server_port = get_available_port()
        cls.http_server = HTTPServer(('127.0.0.1', cls.http_server_port), HTTPRequestHandler)
        cls.http_server_thread = Thread(target=cls.http_server.serve_forever)
        cls.http_server_thread.setDaemon(True)
        cls.http_server_thread.start()
        cls.config = proxy.HttpProtocolConfig()
        cls.config.plugins = proxy.load_plugins('proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.http_server_thread.join()

    def setUp(self):
        self._conn = MockTcpConnection()
        self._addr = ('127.0.0.1', 54382)
        self.proxy = proxy.HttpProtocolHandler(proxy.TcpClientConnection(self._conn, self._addr), config=self.config)

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_http_get(self, mock_server_connection, mock_select):
        server = mock_server_connection.return_value
        server.connect.return_value = True
        mock_select.side_effect = [([self._conn], [], []), ([self._conn], [], []), ([], [server.conn], [])]

        # Send request line
        self.proxy.client.conn.queue((b'GET http://localhost:%d HTTP/1.1' % self.http_server_port) + proxy.CRLF)
        self.proxy.run_once()
        self.assertEqual(self.proxy.request.state, proxy.HttpParser.states.LINE_RCVD)
        self.assertNotEqual(self.proxy.request.state, proxy.HttpParser.states.COMPLETE)

        # Send headers and blank line, thus completing HTTP request
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ]))
        self.proxy.run_once()
        self.assertEqual(self.proxy.request.state, proxy.HttpParser.states.COMPLETE)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False
        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Via: %s' % b'1.1 proxy.py v%s' % proxy.version,
            b'Connection: Close',
            proxy.CRLF
        ]))

        self.proxy.run_once()
        server.flush.assert_called_once()

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_http_tunnel(self, mock_server_connection, mock_select):
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.has_buffer.side_effect = [False, False, False, True]
        mock_select.side_effect = [([self._conn], [], []), ([], [self._conn], []),
                                   ([self._conn], [], []), ([], [server.conn], [])]

        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ]))
        self.proxy.run_once()
        self.assertFalse(self.proxy.plugins['HttpProxyPlugin'].server is None)
        self.assertEqual(self.proxy.client.buffer, proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = proxy.HttpParser(proxy.HttpParser.types.RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, proxy.HttpParser.states.HEADERS_COMPLETE)
        self.assertEqual(int(parser.code), 200)

        # Dispatch tunnel established response to client
        self.proxy.run_once()
        self.assertEqual(self.proxy.client.buffer_size(), 0)

        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ]))
        self.proxy.run_once()
        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ]))
        server.flush.assert_not_called()

        self.proxy.run_once()
        self.assertEqual(server.queue.call_count, 1)
        server.flush.assert_called_once()

    @mock.patch('select.select')
    def test_proxy_connection_failed(self, mock_select):
        mock_select.return_value = ([self._conn], [], [])
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET http://unknown.domain HTTP/1.1',
            b'Host: unknown.domain',
            proxy.CRLF
        ]))
        with self.assertRaises(proxy.ProxyConnectionFailed):
            self.proxy.run_once()

    @mock.patch('select.select')
    def test_proxy_authentication_failed(self, mock_select):
        mock_select.return_value = ([self._conn], [], [])
        config = proxy.HttpProtocolConfig(auth_code=b'Basic %s' % base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins('proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(proxy.TcpClientConnection(self._conn, self._addr),
                                               config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            proxy.CRLF
        ]))
        with self.assertRaises(proxy.ProxyAuthenticationFailed):
            self.proxy.run_once()

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_get(self, mock_server_connection, mock_select):
        mock_select.return_value = ([self._conn], [], [])
        server = mock_server_connection.return_value
        server.connect.return_value = True

        client = proxy.TcpClientConnection(self._conn, self._addr)
        config = proxy.HttpProtocolConfig(auth_code=b'Basic %s' % base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins('proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.HttpProtocolHandler(client, config=config)
        self.proxy.client.conn.queue(b'GET http://localhost:%d HTTP/1.1' % self.http_server_port)
        self.proxy.run_once()
        self.assertEqual(self.proxy.request.state, proxy.HttpParser.states.INITIALIZED)

        self.proxy.client.conn.queue(proxy.CRLF)
        self.proxy.run_once()
        self.assertEqual(self.proxy.request.state, proxy.HttpParser.states.LINE_RCVD)

        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ]))
        self.proxy.run_once()
        self.assertEqual(self.proxy.request.state, proxy.HttpParser.states.COMPLETE)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False

        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Via: %s' % b'1.1 proxy.py v%s' % proxy.version,
            b'Connection: Close',
            proxy.CRLF
        ]))

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_tunnel(self, mock_server_connection, mock_select):
        server = mock_server_connection.return_value
        server.connect.return_value = True
        mock_select.side_effect = [([self._conn], [], []), ([self._conn], [], []), ([], [server.conn], [])]

        config = proxy.HttpProtocolConfig(auth_code=b'Basic %s' % base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins('proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(proxy.TcpClientConnection(self._conn, self._addr),
                                               config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ]))
        self.proxy.run_once()
        self.assertFalse(self.proxy.plugins['HttpProxyPlugin'].server is None)
        self.assertEqual(self.proxy.client.buffer, proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False

        parser = proxy.HttpParser(proxy.HttpParser.types.RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, proxy.HttpParser.states.HEADERS_COMPLETE)
        self.assertEqual(int(parser.code), 200)
        self.proxy.client.flush()
        self.assertEqual(self.proxy.client.buffer_size(), 0)

        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ]))
        self.proxy.run_once()
        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ]))

        self.proxy.run_once()
        server.flush.assert_called_once()


class TestWorker(unittest.TestCase):

    def setUp(self):
        self.queue = multiprocessing.Queue()
        self.worker = proxy.Worker(self.queue)

    @mock.patch('proxy.HttpProtocolHandler')
    def test_shutdown_op(self, mock_http_proxy):
        self.queue.put((proxy.Worker.operations.SHUTDOWN, None))
        self.worker.run()  # Worker should consume the prior shutdown operation
        self.assertFalse(mock_http_proxy.called)

    @mock.patch('proxy.HttpProtocolHandler')
    def test_spawns_http_proxy_threads(self, mock_http_proxy):
        self.queue.put((proxy.Worker.operations.HTTP_PROTOCOL, None))
        self.queue.put((proxy.Worker.operations.SHUTDOWN, None))
        self.worker.run()
        self.assertTrue(mock_http_proxy.called)


class TestMain(unittest.TestCase):

    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    def test_http_server_called(self, mock_set_open_file_limit, mock_http_server):
        proxy.main()
        self.assertTrue(mock_set_open_file_limit.called)
        self.assertTrue(mock_http_server.called)

    def test_text(self):
        self.assertEqual(proxy.text_(b'hello'), 'hello')

    def test_bytes(self):
        self.assertEqual(proxy.bytes_('hello'), b'hello')


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
