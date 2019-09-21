# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    Lightweight Programmable HTTP, HTTPS, WebSockets Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import base64
import errno
import logging
import multiprocessing
import os
import socket
import time
import unittest
from contextlib import closing
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Dict
from unittest import mock

import proxy

if os.name != 'nt':
    import resource

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')


def get_available_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return port


class TestTcpConnection(unittest.TestCase):

    def testHandlesIOError(self):
        self.conn = proxy.TcpConnection(proxy.TcpConnection.types.CLIENT)
        _conn = mock.MagicMock()
        _conn.recv.side_effect = IOError()
        self.conn.conn = _conn
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_called()
            logging.info(mock_logger.exception.call_args[0][0].startswith(
                'Exception while receiving from connection'))

    def testHandlesConnReset(self):
        self.conn = proxy.TcpConnection(proxy.TcpConnection.types.CLIENT)
        _conn = mock.MagicMock()
        e = IOError()
        e.errno = errno.ECONNRESET
        _conn.recv.side_effect = e
        self.conn.conn = _conn
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_not_called()
            mock_logger.debug.assert_called()
            self.assertEqual(mock_logger.debug.call_args[0][0], '%r' % e)

    def testClosesIfNotClosed(self):
        self.conn = proxy.TcpConnection(proxy.TcpConnection.types.CLIENT)
        _conn = mock.MagicMock()
        self.conn.conn = _conn
        self.conn.close()
        _conn.close.assert_called()
        self.assertTrue(self.conn.closed)

    def testNoOpIfAlreadyClosed(self):
        self.conn = proxy.TcpConnection(proxy.TcpConnection.types.CLIENT)
        _conn = mock.MagicMock()
        self.conn.conn = _conn
        self.conn.closed = True
        self.conn.close()
        _conn.close.assert_not_called()
        self.assertTrue(self.conn.closed)

    @mock.patch('socket.create_connection')
    def testTcpServerClosesConnOnGC(self, mock_create_connection):
        conn = mock.MagicMock()
        mock_create_connection.return_value = conn
        self.conn = proxy.TcpServerConnection(
            proxy.DEFAULT_IPV4_HOSTNAME, proxy.DEFAULT_PORT)
        self.conn.connect()
        del self.conn
        conn.close.assert_called()


@unittest.skipIf(os.getenv('TESTING_ON_TRAVIS', 0),
                 'Opening sockets not allowed on Travis')
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

        def setup(self) -> None:
            pass

        def shutdown(self) -> None:
            pass

    @classmethod
    def setUpClass(cls):
        cls.ipv4_port = get_available_port()
        cls.ipv6_port = get_available_port()
        cls.ipv4_server = TestTcpServer._TestTcpServer(
            port=cls.ipv4_port, ipv4=True)
        cls.ipv6_server = TestTcpServer._TestTcpServer(
            hostname=proxy.DEFAULT_IPV6_HOSTNAME, port=cls.ipv6_port, ipv4=False)
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
                sock = socket.socket(
                    socket.AF_INET if ipv4 else socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0)
                sock.connect(
                    (proxy.DEFAULT_IPV4_HOSTNAME if ipv4 else proxy.DEFAULT_IPV6_HOSTNAME,
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


class MockHttpProxy:

    def __init__(self, client, **kwargs):
        self.client = client
        self.kwargs = kwargs

    def setDaemon(self, _val):
        pass

    def start(self):
        self.client.conn.sendall(proxy.CRLF.join(
            [b'HTTP/1.1 200 OK', proxy.CRLF]))
        self.client.conn.close()


def mock_tcp_proxy_side_effect(client, **kwargs):
    return MockHttpProxy(client, **kwargs)


@unittest.skipIf(os.getenv('TESTING_ON_TRAVIS', 0),
                 'Opening sockets not allowed on Travis')
class TestMultiCoreRequestDispatcher(unittest.TestCase):
    tcp_port = None
    tcp_server = None
    tcp_thread = None

    @mock.patch.object(
        proxy,
        'HttpProtocolHandler',
        side_effect=mock_tcp_proxy_side_effect)
    def testHttpProxyConnection(self, _mock_tcp_proxy):
        try:
            self.tcp_port = get_available_port()
            self.tcp_server = proxy.MultiCoreRequestDispatcher(
                hostname=proxy.DEFAULT_IPV4_HOSTNAME,
                port=self.tcp_port,
                ipv4=True,
                num_workers=1)
            self.tcp_thread = Thread(target=self.tcp_server.run)
            self.tcp_thread.setDaemon(True)
            self.tcp_thread.start()

            while True:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
                    try:
                        sock.connect(
                            (proxy.DEFAULT_IPV4_HOSTNAME, self.tcp_port))
                        sock.send(proxy.CRLF.join([
                            b'GET http://httpbin.org/get HTTP/1.1',
                            b'Host: httpbin.org',
                            proxy.CRLF
                        ]))
                        data = sock.recv(proxy.DEFAULT_BUFFER_SIZE)
                        self.assertEqual(data, proxy.CRLF.join(
                            [b'HTTP/1.1 200 OK', proxy.CRLF]))
                        break
                    except ConnectionRefusedError:
                        time.sleep(0.1)
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
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 3)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_DATA)
        self.parser.parse(b'abc')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'4\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 4)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_DATA)
        self.parser.parse(b'defg\r\n0')
        self.assertEqual(self.parser.chunk, b'0')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(
            self.parser.state,
            proxy.ChunkParser.states.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, proxy.ChunkParser.states.COMPLETE)


class TestHttpParser(unittest.TestCase):

    def setUp(self):
        self.parser = proxy.HttpParser(proxy.HttpParser.types.REQUEST_PARSER)

    def test_build_header(self):
        self.assertEqual(
            proxy.HttpParser.build_header(
                b'key', b'value'), b'key: value')

    def test_find_line(self):
        self.assertEqual(
            proxy.HttpParser.find_line(b'CONNECT python.org:443 HTTP/1.0\r\n\r\n'),
            (b'CONNECT python.org:443 HTTP/1.0',
             b'\r\n'))

    def test_find_line_returns_None(self):
        self.assertEqual(
            proxy.HttpParser.find_line(b'CONNECT python.org:443 HTTP/1.0'),
            (None,
             b'CONNECT python.org:443 HTTP/1.0'))

    def test_pip_connect(self):
        raw = b'CONNECT pypi.org:443 HTTP/1.0\r\n'
        self.parser.parse(raw)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)

    def test_get_full_parse(self):
        raw = proxy.CRLF.join([
            b'GET %s HTTP/1.1',
            b'Host: %s',
            proxy.CRLF
        ])
        pkt = raw % (b'https://example.com/path/dir/?a=b&c=d#p=q',
                     b'example.com')
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.build_url(), b'/path/dir/?a=b&c=d#p=q')
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.parser.del_headers([b'host'])
        self.parser.add_headers([(b'Host', b'example.com')])
        self.assertEqual(
            raw %
            (b'/path/dir/?a=b&c=d#p=q',
             b'example.com'),
            self.parser.build())

    def test_build_url_none(self):
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self):
        pkt = b'GET http://localhost HTTP/1.1'
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assert_state_change_with_crlf(
            proxy.HttpParser.states.INITIALIZED,
            proxy.HttpParser.states.LINE_RCVD,
            proxy.HttpParser.states.COMPLETE)

    def test_get_partial_parse1(self):
        pkt = proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1'
        ])
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assertEqual(self.parser.method, None)
        self.assertEqual(self.parser.url, None)
        self.assertEqual(self.parser.version, None)
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.INITIALIZED)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.total_size, len(pkt) + len(proxy.CRLF))
        self.assertEqual(self.parser.method, b'GET')
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)

        host_hdr = b'Host: localhost:8080'
        self.parser.parse(host_hdr)
        self.assertEqual(self.parser.total_size,
                         len(pkt) + len(proxy.CRLF) + len(host_hdr))
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.LINE_RCVD)

        self.parser.parse(proxy.CRLF * 2)
        self.assertEqual(self.parser.total_size, len(pkt) +
                         (3 * len(proxy.CRLF)) + len(host_hdr))
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
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
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + proxy.CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.RCVING_HEADERS)

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
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')}, self.parser.headers)
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def assert_state_change_with_crlf(self,
                                      initial_state: proxy.HttpParser.states,
                                      next_state: proxy.HttpParser.states,
                                      final_state: proxy.HttpParser.states):
        self.assertEqual(self.parser.state, initial_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, next_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, final_state)

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
        self.assert_state_change_with_crlf(
            proxy.HttpParser.states.RCVING_HEADERS,
            proxy.HttpParser.states.RCVING_HEADERS,
            proxy.HttpParser.states.HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.RCVING_BODY)
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
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.HEADERS_COMPLETE)

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
        self.assertEqual(
            self.parser.body,
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'219')}, self.parser.headers)
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
        self.assertDictContainsSubset(
            {b'x-frame-options': (b'X-Frame-Options', b'SAMEORIGIN')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(
            self.parser.state,
            proxy.HttpParser.states.RCVING_BODY)
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

    def assertDictContainsSubset(self, subset: Dict, dictionary: Dict):
        for k in subset.keys():
            self.assertTrue(k in dictionary)


class MockTcpConnection:

    def __init__(self, b=b''):
        self.buffer = b
        self.received = b''
        self.closed = False

    def recv(self, b=8192) -> bytes:
        data = self.buffer[:b]
        self.buffer = self.buffer[b:]
        return data

    def send(self, data: bytes) -> int:
        self.received += data
        return len(data)

    def queue(self, data: bytes):
        self.buffer += data

    def close(self):
        self.closed = True


class HTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        # TODO(abhinavsingh): Proxy should work just fine even without
        # content-length header
        self.send_header('content-length', 2)
        self.end_headers()
        self.wfile.write(b'OK')


class TestHttpProtocolHandler(unittest.TestCase):
    http_server = None
    http_server_port = None
    http_server_thread = None
    config = None

    @classmethod
    def setUpClass(cls):
        cls.http_server_port = get_available_port()
        cls.http_server = HTTPServer(
            ('127.0.0.1', cls.http_server_port), HTTPRequestHandler)
        cls.http_server_thread = Thread(target=cls.http_server.serve_forever)
        cls.http_server_thread.setDaemon(True)
        cls.http_server_thread.start()
        cls.config = proxy.HttpProtocolConfig()
        cls.config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

    @classmethod
    def tearDownClass(cls):
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.http_server_thread.join()

    def setUp(self):
        self._conn = MockTcpConnection()
        self._addr = ('127.0.0.1', 54382)
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=self.config)

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_http_get(self, mock_server_connection, mock_select):
        server = mock_server_connection.return_value
        server.connect.return_value = True
        mock_select.side_effect = [
            ([self._conn], [], []), ([self._conn], [], []), ([], [server.conn], [])]

        # Send request line
        self.proxy.client.conn.queue(
            (b'GET http://localhost:%d HTTP/1.1' %
             self.http_server_port) + proxy.CRLF)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.LINE_RCVD)
        self.assertNotEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.COMPLETE)

        # Send headers and blank line, thus completing HTTP request
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ]))
        self.assert_data_queued(mock_server_connection, server)
        self.proxy.run_once()
        server.flush.assert_called_once()

    def assert_tunnel_response(self, mock_server_connection, server):
        self.proxy.run_once()
        self.assertFalse(self.proxy.plugins['HttpProxyPlugin'].server is None)
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = proxy.HttpParser(proxy.HttpParser.types.RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, proxy.HttpParser.states.COMPLETE)
        self.assertEqual(int(parser.code), 200)

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
        self.assert_tunnel_response(mock_server_connection, server)

        # Dispatch tunnel established response to client
        self.proxy.run_once()
        self.assert_data_queued_to_server(server)

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
        config = proxy.HttpProtocolConfig(
            auth_code=b'Basic %s' %
            base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            proxy.CRLF
        ]))
        with self.assertRaises(proxy.ProxyAuthenticationFailed):
            self.proxy.run_once()

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_get(
            self, mock_server_connection, mock_select):
        mock_select.return_value = ([self._conn], [], [])
        server = mock_server_connection.return_value
        server.connect.return_value = True

        client = proxy.TcpClientConnection(self._conn, self._addr)
        config = proxy.HttpProtocolConfig(
            auth_code=b'Basic %s' %
            base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.HttpProtocolHandler(client, config=config)
        self.proxy.client.conn.queue(
            b'GET http://localhost:%d HTTP/1.1' %
            self.http_server_port)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.INITIALIZED)

        self.proxy.client.conn.queue(proxy.CRLF)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.LINE_RCVD)

        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ]))
        self.assert_data_queued(mock_server_connection, server)

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_tunnel(
            self, mock_server_connection, mock_select):
        server = mock_server_connection.return_value
        server.connect.return_value = True
        mock_select.side_effect = [
            ([self._conn], [], []), ([self._conn], [], []), ([], [server.conn], [])]

        config = proxy.HttpProtocolConfig(
            auth_code=b'Basic %s' %
            base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ]))
        self.assert_tunnel_response(mock_server_connection, server)
        self.proxy.client.flush()
        self.assert_data_queued_to_server(server)

        self.proxy.run_once()
        server.flush.assert_called_once()

    @mock.patch('select.select')
    def test_pac_file_served_from_disk(self, mock_select):
        mock_select.return_value = [self._conn], [], []
        config = proxy.HttpProtocolConfig(pac_file='proxy.pac')
        self.init_and_make_pac_file_request(config)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.COMPLETE)
        with open('proxy.pac', 'rb') as pac_file:
            self.assertEqual(
                self._conn.received,
                proxy.HttpWebServerPlugin.PAC_FILE_RESPONSE_PREFIX +
                pac_file.read())

    @mock.patch('select.select')
    def test_pac_file_served_from_buffer(self, mock_select):
        pac_file_content = b'function FindProxyForURL(url, host) { return "PROXY localhost:8899; DIRECT"; }'
        mock_select.return_value = [self._conn], [], []
        config = proxy.HttpProtocolConfig(pac_file=pac_file_content)
        self.init_and_make_pac_file_request(config)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.COMPLETE)
        self.assertEqual(
            self._conn.received,
            proxy.HttpWebServerPlugin.PAC_FILE_RESPONSE_PREFIX +
            pac_file_content)

    @mock.patch('select.select')
    def test_default_web_server_returns_404(self, mock_select):
        mock_select.return_value = [self._conn], [], []
        config = proxy.HttpProtocolConfig()
        config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET /hello HTTP/1.1',
            proxy.CRLF,
            proxy.CRLF
        ]))
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.COMPLETE)
        self.assertEqual(
            self._conn.received,
            proxy.HttpWebServerPlugin.DEFAULT_404_RESPONSE)

    def test_on_client_connection_called_on_teardown(self):
        config = proxy.HttpProtocolConfig()
        plugin = mock.MagicMock()
        config.plugins = {'HttpProtocolBasePlugin': [plugin]}
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=config)
        plugin.assert_called()
        with mock.patch.object(self.proxy, 'run_once') as mock_run_once:
            mock_run_once.return_value = True
            self.proxy.run()
        self.assertTrue(self._conn.closed)
        plugin.return_value.access_log.assert_called()
        plugin.return_value.on_client_connection_close.assert_called()

    def init_and_make_pac_file_request(self, config):
        config.plugins = proxy.load_plugins(
            'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.HttpProtocolHandler(
            proxy.TcpClientConnection(
                self._conn, self._addr), config=config)
        self.proxy.client.conn.queue(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            proxy.CRLF,
            proxy.CRLF
        ]))

    def assert_data_queued(self, mock_server_connection, server):
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.HttpParser.states.COMPLETE)
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

    def assert_data_queued_to_server(self, server):
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


class TestWorker(unittest.TestCase):

    def setUp(self):
        self.pipe = multiprocessing.Pipe()
        self.worker = proxy.Worker(self.pipe[1])

    @mock.patch('proxy.HttpProtocolHandler')
    def test_shutdown_op(self, mock_http_proxy):
        self.pipe[0].send((proxy.Worker.operations.SHUTDOWN, None))
        self.worker.run()  # Worker should consume the prior shutdown operation
        self.assertFalse(mock_http_proxy.called)

    @mock.patch('proxy.HttpProtocolHandler')
    def test_spawns_http_proxy_threads(self, mock_http_proxy):
        self.pipe[0].send((proxy.Worker.operations.HTTP_PROTOCOL, None))
        self.pipe[0].send((proxy.Worker.operations.SHUTDOWN, None))
        self.worker.run()
        self.assertTrue(mock_http_proxy.called)


class TestHttpRequestRejected(unittest.TestCase):

    def setUp(self):
        self.request = proxy.HttpParser(proxy.HttpParser.types.REQUEST_PARSER)

    def test_empty_response(self):
        e = proxy.HttpRequestRejected()
        self.assertEqual(e.response(self.request), None)

    def test_status_code_response(self):
        e = proxy.HttpRequestRejected(status_code=b'200 OK')
        self.assertEqual(e.response(self.request), proxy.CRLF.join([
            b'HTTP/1.1 200 OK',
            proxy.PROXY_AGENT_HEADER,
            proxy.CRLF
        ]))

    def test_body_response(self):
        e = proxy.HttpRequestRejected(
            status_code=b'404 NOT FOUND',
            body=b'Nothing here')
        self.assertEqual(e.response(self.request), proxy.CRLF.join([
            b'HTTP/1.1 404 NOT FOUND',
            proxy.PROXY_AGENT_HEADER,
            b'Content-Length: 12',
            proxy.CRLF,
            b'Nothing here'
        ]))


class TestMain(unittest.TestCase):

    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    @mock.patch('proxy.logging.basicConfig')
    def test_log_file_setup(
            self,
            mock_config,
            mock_multicore_dispatcher,
            mock_set_open_file_limit):
        log_file = '/tmp/proxy.log'
        proxy.main(['--log-file', log_file])
        mock_set_open_file_limit.assert_called()
        mock_multicore_dispatcher.assert_called()
        mock_multicore_dispatcher.return_value.run.assert_called()
        mock_config.assert_called_with(
            filename=log_file,
            filemode='a',
            level=proxy.logging.INFO,
            format=proxy.DEFAULT_LOG_FORMAT
        )

    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    @unittest.skipIf(
        True,
        'This test passes while development on Intellij but fails via CLI :(')
    def test_pid_file_is_written_and_removed(
            self,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_open,
            mock_exists,
            mock_remove):
        pid_file = '/tmp/proxy.pid'
        proxy.main(['--pid-file', pid_file])
        mock_set_open_file_limit.assert_called()
        mock_multicore_dispatcher.assert_called()
        mock_multicore_dispatcher.return_value.run.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            proxy.bytes_(str(os.getpid())))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('proxy.HttpProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    def test_main(
            self,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_config):
        proxy.main(['--basic-auth', 'user:pass'])
        self.assertTrue(mock_set_open_file_limit.called)
        mock_multicore_dispatcher.assert_called_with(
            hostname=proxy.DEFAULT_IPV4_HOSTNAME,
            port=proxy.DEFAULT_PORT,
            ipv4=proxy.DEFAULT_IPV4,
            backlog=proxy.DEFAULT_BACKLOG,
            num_workers=proxy.DEFAULT_NUM_WORKERS,
            config=mock_config.return_value)
        mock_config.assert_called_with(
            auth_code=b'Basic dXNlcjpwYXNz',
            client_recvbuf_size=proxy.DEFAULT_CLIENT_RECVBUF_SIZE,
            server_recvbuf_size=proxy.DEFAULT_SERVER_RECVBUF_SIZE,
            pac_file=proxy.DEFAULT_PAC_FILE,
            pac_file_url_path=proxy.DEFAULT_PAC_FILE_URL_PATH,
            disable_headers=proxy.DEFAULT_DISABLE_HEADERS
        )

    @mock.patch('builtins.print')
    @mock.patch('proxy.HttpProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    def test_main_version(
            self,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_config,
            mock_print):
        with self.assertRaises(SystemExit):
            proxy.main(['--version'])
            mock_print.assert_called_with(proxy.text_(proxy.version))
        mock_multicore_dispatcher.assert_not_called()
        mock_set_open_file_limit.assert_not_called()
        mock_config.assert_not_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.HttpProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    @mock.patch('proxy.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_config,
            mock_print):
        mock_is_py3.return_value = True
        proxy.main([])
        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_multicore_dispatcher.assert_called()
        mock_set_open_file_limit.assert_called()
        mock_config.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.HttpProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.MultiCoreRequestDispatcher')
    @mock.patch('proxy.is_py3')
    @unittest.skipIf(
        True,
        'This test passes while development on Intellij but fails via CLI :(')
    def test_main_py2_exit(
            self,
            mock_is_py3,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_config,
            mock_print):
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit):
            proxy.main([])
            mock_print.assert_called_with('DEPRECATION')
            mock_is_py3.assert_called()
        mock_multicore_dispatcher.assert_not_called()
        mock_set_open_file_limit.assert_not_called()
        mock_config.assert_not_called()

    def test_text(self):
        self.assertEqual(proxy.text_(b'hello'), 'hello')

    def test_text_nochange(self):
        self.assertEqual(proxy.text_('hello'), 'hello')

    def test_bytes(self):
        self.assertEqual(proxy.bytes_('hello'), b'hello')

    def test_bytes_nochange(self):
        self.assertEqual(proxy.bytes_(b'hello'), b'hello')

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(128, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit(self, mock_set_rlimit, mock_get_rlimit):
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_called_with(resource.RLIMIT_NOFILE, (256, 1024))

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called(
            self, mock_set_rlimit, mock_get_rlimit):
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(256, 1024))
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called1(
            self, mock_set_rlimit, mock_get_rlimit):
        proxy.set_open_file_limit(1024)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
