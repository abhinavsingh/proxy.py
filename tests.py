# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    Lightweight, Programmable, TLS interceptor Proxy for HTTP(S), HTTP2, WebSockets protocols in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import ssl
import base64
import errno
import logging
import multiprocessing
import os
import socket
import tempfile
import time
import unittest
from contextlib import closing
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Dict, Optional, Tuple, Union
from unittest import mock

import proxy

if os.name != 'nt':
    import resource

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')


def get_temp_file(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), name)


def get_available_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(('', 0))
        _, port = sock.getsockname()
        return int(port)


class TestTcpConnection(unittest.TestCase):

    class TcpConnectionToTest(proxy.TcpConnection):

        def __init__(self, conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None,
                     tag: int = proxy.tcpConnectionTypes.CLIENT) -> None:
            super().__init__(tag)
            self._conn = conn

        @property
        def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
            if self._conn is None:
                raise proxy.TcpConnectionUninitializedException()
            return self._conn

    def testThrowsKeyErrorIfNoConn(self) -> None:
        self.conn = TestTcpConnection.TcpConnectionToTest()
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.send(b'dummy')
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.recv()
        with self.assertRaises(proxy.TcpConnectionUninitializedException):
            self.conn.close()

    def testHandlesIOError(self) -> None:
        _conn = mock.MagicMock()
        _conn.recv.side_effect = IOError()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_called()
            logging.info(mock_logger.exception.call_args[0][0].startswith(
                'Exception while receiving from connection'))

    def testHandlesConnReset(self) -> None:
        _conn = mock.MagicMock()
        e = IOError()
        e.errno = errno.ECONNRESET
        _conn.recv.side_effect = e
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        with mock.patch('proxy.logger') as mock_logger:
            self.conn.recv()
            mock_logger.exception.assert_not_called()
            mock_logger.debug.assert_called()
            self.assertEqual(mock_logger.debug.call_args[0][0], '%r' % e)

    def testClosesIfNotClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.close()
        _conn.close.assert_called()
        self.assertTrue(self.conn.closed)

    def testNoOpIfAlreadyClosed(self) -> None:
        _conn = mock.MagicMock()
        self.conn = TestTcpConnection.TcpConnectionToTest(_conn)
        self.conn.closed = True
        self.conn.close()
        _conn.close.assert_not_called()
        self.assertTrue(self.conn.closed)

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv6Connection(
            self, mock_socket: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(proxy.DEFAULT_IPV6_HOSTNAME), proxy.DEFAULT_PORT, 0, 0))

    @mock.patch('socket.socket')
    def testTcpServerEstablishesIPv4Connection(
            self, mock_socket: mock.Mock) -> None:
        conn = proxy.TcpServerConnection(
            str(proxy.DEFAULT_IPV4_HOSTNAME), proxy.DEFAULT_PORT)
        conn.connect()
        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(
            (str(proxy.DEFAULT_IPV4_HOSTNAME), proxy.DEFAULT_PORT))


class TcpServerUnderTest(proxy.TcpServer):

    def handle(self, client: proxy.TcpClientConnection) -> None:
        data = client.recv(proxy.DEFAULT_BUFFER_SIZE)
        if data != b'HELLO':
            raise ValueError('Expected HELLO')
        client.connection.sendall(b'WORLD')
        client.close()

    def setup(self) -> None:
        pass

    def shutdown(self) -> None:
        pass


@unittest.skipIf(os.getenv('TESTING_ON_TRAVIS', 0),
                 'Opening sockets not allowed on Travis')
class TestTcpServerIntegration(unittest.TestCase):

    ipv4_port: Optional[int] = None
    ipv6_port: Optional[int] = None
    ipv4_server: Optional[TcpServerUnderTest] = None
    ipv6_server: Optional[TcpServerUnderTest] = None
    ipv4_thread: Optional[Thread] = None
    ipv6_thread: Optional[Thread] = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.ipv4_port = get_available_port()
        cls.ipv6_port = get_available_port()
        cls.ipv4_server = TcpServerUnderTest(
            hostname=proxy.DEFAULT_IPV4_HOSTNAME,
            port=cls.ipv4_port)
        cls.ipv6_server = TcpServerUnderTest(
            hostname=proxy.DEFAULT_IPV6_HOSTNAME,
            port=cls.ipv6_port)
        cls.ipv4_thread = Thread(target=cls.ipv4_server.run)
        cls.ipv6_thread = Thread(target=cls.ipv6_server.run)
        cls.ipv4_thread.setDaemon(True)
        cls.ipv6_thread.setDaemon(True)
        cls.ipv4_thread.start()
        cls.ipv6_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.ipv4_server:
            cls.ipv4_server.stop()
        if cls.ipv4_thread:
            cls.ipv4_thread.join()
        if cls.ipv6_server:
            cls.ipv6_server.stop()
        if cls.ipv6_thread:
            cls.ipv6_thread.join()

    def baseTestCase(self, ipv4: bool = True) -> None:
        while True:
            sock = None
            try:
                sock = socket.socket(
                    socket.AF_INET if ipv4 else socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0)
                sock.connect(
                    (str(
                        proxy.DEFAULT_IPV4_HOSTNAME if ipv4 else proxy.DEFAULT_IPV6_HOSTNAME),
                     self.ipv4_port if ipv4 else self.ipv6_port))
                sock.sendall(b'HELLO')
                data = sock.recv(proxy.DEFAULT_BUFFER_SIZE)
                self.assertEqual(data, b'WORLD')
                break
            except ConnectionRefusedError:
                time.sleep(0.1)
            finally:
                if sock:
                    sock.close()

    def testIpv4ClientConnection(self) -> None:
        self.baseTestCase()

    def testIpv6ClientConnection(self) -> None:
        self.baseTestCase(ipv4=False)


class TestTcpServer(unittest.TestCase):

    # Can happen if client is sending invalid https request to our SSL server.
    # Example, simply sending http traffic to HTTPS server.
    @mock.patch('select.select')
    @mock.patch('socket.socket')
    def testAcceptSSLErrorsSilentlyIgnored(
            self, mock_socket: mock.Mock, mock_select: mock.Mock) -> None:
        mock_socket.accept.side_effect = ssl.SSLError()
        mock_select.return_value = ([mock_socket], [], [])
        server = TcpServerUnderTest(
            hostname=proxy.DEFAULT_IPV6_HOSTNAME, port=1234)
        server.socket = mock_socket
        with mock.patch('proxy.logger') as mock_logger:
            server.run_once()
            mock_logger.exception.assert_called()
            self.assertTrue(
                mock_logger.exception.call_args[0][0],
                'SSLError encountered')


class TestChunkParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = proxy.ChunkParser()

    def test_chunk_parse_basic(self) -> None:
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
        self.assertEqual(self.parser.state, proxy.chunkParserStates.COMPLETE)

    def test_chunk_parse_issue_27(self) -> None:
        """Case when data ends with the chunk size but without ending CRLF."""
        self.parser.parse(b'3')
        self.assertEqual(self.parser.chunk, b'3')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 3)
        self.assertEqual(self.parser.body, b'')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_DATA)
        self.parser.parse(b'abc')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'4\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, 4)
        self.assertEqual(self.parser.body, b'abc')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_DATA)
        self.parser.parse(b'defg\r\n0')
        self.assertEqual(self.parser.chunk, b'0')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(
            self.parser.state,
            proxy.chunkParserStates.WAITING_FOR_SIZE)
        self.parser.parse(b'\r\n\r\n')
        self.assertEqual(self.parser.chunk, b'')
        self.assertEqual(self.parser.size, None)
        self.assertEqual(self.parser.body, b'abcdefg')
        self.assertEqual(self.parser.state, proxy.chunkParserStates.COMPLETE)


class TestHttpParser(unittest.TestCase):

    def setUp(self) -> None:
        self.parser = proxy.HttpParser(proxy.httpParserTypes.REQUEST_PARSER)

    def test_build_request(self) -> None:
        self.assertEqual(
            proxy.HttpParser.build_request(
                b'GET', b'http://localhost:12345', b'HTTP/1.1'),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.HttpParser.build_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                                           headers={b'key': b'value'}),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.HttpParser.build_request(b'GET', b'http://localhost:12345', b'HTTP/1.1',
                                           headers={b'key': b'value'},
                                           body=b'Hello from proxy.py'),
            proxy.CRLF.join([
                b'GET http://localhost:12345 HTTP/1.1',
                b'key: value',
                proxy.CRLF
            ]) + b'Hello from proxy.py')

    def test_build_response(self) -> None:
        self.assertEqual(
            proxy.HttpParser.build_response(
                200, reason=b'OK', protocol_version=b'HTTP/1.1'),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                proxy.CRLF
            ]))
        self.assertEqual(
            proxy.HttpParser.build_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                            headers={b'key': b'value'}),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                proxy.CRLF
            ]))

    def test_build_response_adds_content_length_header(self) -> None:
        body = b'Hello world!!!'
        self.assertEqual(
            proxy.HttpParser.build_response(200, reason=b'OK', protocol_version=b'HTTP/1.1',
                                            headers={b'key': b'value'},
                                            body=body),
            proxy.CRLF.join([
                b'HTTP/1.1 200 OK',
                b'key: value',
                b'Content-Length: ' + proxy.bytes_(len(body)),
                proxy.CRLF
            ]) + body)

    def test_build_header(self) -> None:
        self.assertEqual(
            proxy.HttpParser.build_header(
                b'key', b'value'), b'key: value')

    def test_find_line(self) -> None:
        self.assertEqual(
            proxy.HttpParser.find_line(
                b'CONNECT python.org:443 HTTP/1.0\r\n\r\n'),
            (b'CONNECT python.org:443 HTTP/1.0',
             proxy.CRLF))

    def test_find_line_returns_None(self) -> None:
        self.assertEqual(
            proxy.HttpParser.find_line(b'CONNECT python.org:443 HTTP/1.0'),
            (None,
             b'CONNECT python.org:443 HTTP/1.0'))

    def test_connect_request_with_crlf_as_separate_chunk(self) -> None:
        """See https://github.com/abhinavsingh/proxy.py/issues/70 for background."""
        raw = b'CONNECT pypi.org:443 HTTP/1.0\r\n'
        self.parser.parse(raw)
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_get_full_parse(self) -> None:
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
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'example.com')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'example.com')}, self.parser.headers)
        self.parser.del_headers([b'host'])
        self.parser.add_headers([(b'Host', b'example.com')])
        self.assertEqual(
            raw %
            (b'/path/dir/?a=b&c=d#p=q',
             b'example.com'),
            self.parser.build())

    def test_build_url_none(self) -> None:
        self.assertEqual(self.parser.build_url(), b'/None')

    def test_line_rcvd_to_rcving_headers_state_change(self) -> None:
        pkt = b'GET http://localhost HTTP/1.1'
        self.parser.parse(pkt)
        self.assertEqual(self.parser.total_size, len(pkt))
        self.assert_state_change_with_crlf(
            proxy.httpParserStates.INITIALIZED,
            proxy.httpParserStates.LINE_RCVD,
            proxy.httpParserStates.COMPLETE)

    def test_get_partial_parse1(self) -> None:
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
            proxy.httpParserStates.INITIALIZED)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.total_size, len(pkt) + len(proxy.CRLF))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        host_hdr = b'Host: localhost:8080'
        self.parser.parse(host_hdr)
        self.assertEqual(self.parser.total_size,
                         len(pkt) + len(proxy.CRLF) + len(host_hdr))
        self.assertDictEqual(self.parser.headers, dict())
        self.assertEqual(self.parser.buffer, b'Host: localhost:8080')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        self.parser.parse(proxy.CRLF * 2)
        self.assertEqual(self.parser.total_size, len(pkt) +
                         (3 * len(proxy.CRLF)) + len(host_hdr))
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_get_partial_parse2(self) -> None:
        self.parser.parse(proxy.CRLF.join([
            b'GET http://localhost:8080 HTTP/1.1',
            b'Host: '
        ]))
        self.assertEqual(self.parser.method, b'GET')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, 8080)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertEqual(self.parser.buffer, b'Host: ')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)

        self.parser.parse(b'localhost:8080' + proxy.CRLF)
        self.assertDictContainsSubset(
            {b'host': (b'Host', b'localhost:8080')}, self.parser.headers)
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_HEADERS)

        self.parser.parse(b'Content-Type: text/plain' + proxy.CRLF)
        self.assertEqual(self.parser.buffer, b'')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'text/plain')}, self.parser.headers)
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_HEADERS)

        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_post_full_parse(self) -> None:
        raw = proxy.CRLF.join([
            b'POST %s HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded' + proxy.CRLF,
            b'a=b&c=d'
        ])
        self.parser.parse(raw % b'http://localhost')
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assertDictContainsSubset(
            {b'content-type': (b'Content-Type', b'application/x-www-form-urlencoded')}, self.parser.headers)
        self.assertDictContainsSubset(
            {b'content-length': (b'Content-Length', b'7')}, self.parser.headers)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertEqual(len(self.parser.build()), len(raw % b'/'))

    def assert_state_change_with_crlf(self,
                                      initial_state: int,
                                      next_state: int,
                                      final_state: int) -> None:
        self.assertEqual(self.parser.state, initial_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, next_state)
        self.parser.parse(proxy.CRLF)
        self.assertEqual(self.parser.state, final_state)

    def test_post_partial_parse(self) -> None:
        self.parser.parse(proxy.CRLF.join([
            b'POST http://localhost HTTP/1.1',
            b'Host: localhost',
            b'Content-Length: 7',
            b'Content-Type: application/x-www-form-urlencoded'
        ]))
        self.assertEqual(self.parser.method, b'POST')
        assert self.parser.url
        self.assertEqual(self.parser.url.hostname, b'localhost')
        self.assertEqual(self.parser.url.port, None)
        self.assertEqual(self.parser.version, b'HTTP/1.1')
        self.assert_state_change_with_crlf(
            proxy.httpParserStates.RCVING_HEADERS,
            proxy.httpParserStates.RCVING_HEADERS,
            proxy.httpParserStates.HEADERS_COMPLETE)

        self.parser.parse(b'a=b')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_BODY)
        self.assertEqual(self.parser.body, b'a=b')
        self.assertEqual(self.parser.buffer, b'')

        self.parser.parse(b'&c=d')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)
        self.assertEqual(self.parser.body, b'a=b&c=d')
        self.assertEqual(self.parser.buffer, b'')

    def test_connect_request_without_host_header_request_parse(self) -> None:
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
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_request_parse_without_content_length(self) -> None:
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
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_response_parse_without_content_length(self) -> None:
        """Case when server response doesn't contain a content-length header for non-chunk response types.

        HttpParser by itself has no way to know if more data should be expected.
        In example below, parser reaches state httpParserStates.HEADERS_COMPLETE
        and it is responsibility of callee to change state to httpParserStates.COMPLETE
        when server stream closes.

        See https://github.com/abhinavsingh/proxy.py/issues/20 for details.
        """
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
        self.parser.parse(b'HTTP/1.0 200 OK' + proxy.CRLF)
        self.assertEqual(self.parser.code, b'200')
        self.assertEqual(self.parser.version, b'HTTP/1.0')
        self.assertEqual(self.parser.state, proxy.httpParserStates.LINE_RCVD)
        self.parser.parse(proxy.CRLF.join([
            b'Server: BaseHTTP/0.3 Python/2.7.10',
            b'Date: Thu, 13 Dec 2018 16:24:09 GMT',
            proxy.CRLF
        ]))
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.HEADERS_COMPLETE)

    def test_response_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
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
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_response_partial_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
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
            proxy.httpParserStates.RCVING_HEADERS)
        self.parser.parse(b'\r\n')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.HEADERS_COMPLETE)
        self.parser.parse(
            b'<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n' +
            b'<TITLE>301 Moved</TITLE></HEAD>')
        self.assertEqual(
            self.parser.state,
            proxy.httpParserStates.RCVING_BODY)
        self.parser.parse(
            b'<BODY>\n<H1>301 Moved</H1>\nThe document has moved\n' +
            b'<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n')
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def test_chunked_response_parse(self) -> None:
        self.parser.type = proxy.httpParserTypes.RESPONSE_PARSER
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
        self.assertEqual(self.parser.state, proxy.httpParserStates.COMPLETE)

    def assertDictContainsSubset(self, subset: Dict[bytes, Tuple[bytes, bytes]],
                                 dictionary: Dict[bytes, Tuple[bytes, bytes]]) -> None:
        for k in subset.keys():
            self.assertTrue(k in dictionary)


class TestHttpProtocolHandler(unittest.TestCase):
    http_server = None
    http_server_port = None
    http_server_thread = None
    config = None

    class HTTPRequestHandler(BaseHTTPRequestHandler):

        def do_GET(self) -> None:
            self.send_response(200)
            # TODO(abhinavsingh): Proxy should work just fine even without
            # content-length header
            self.send_header('content-length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    @classmethod
    def setUpClass(cls) -> None:
        cls.http_server_port = get_available_port()
        cls.http_server = HTTPServer(
            ('127.0.0.1', cls.http_server_port), TestHttpProtocolHandler.HTTPRequestHandler)
        cls.http_server_thread = Thread(target=cls.http_server.serve_forever)
        cls.http_server_thread.setDaemon(True)
        cls.http_server_thread.start()
        cls.config = proxy.ProtocolConfig()
        cls.config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.http_server:
            cls.http_server.shutdown()
            cls.http_server.server_close()
        if cls.http_server_thread:
            cls.http_server_thread.join()

    @mock.patch('socket.fromfd')
    def setUp(self, mock_fromfd: mock.Mock) -> None:
        self.fileno = 10
        self._addr = ('127.0.0.1', 54382)
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=self.config)

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_http_get(self, mock_server_connection: mock.Mock,
                      mock_select: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        mock_select.side_effect = [
            ([self._conn], [], []),
            ([self._conn], [], []),
            ([], [server.connection], [])]

        # Send request line
        assert self.http_server_port is not None
        self._conn.recv.return_value = (b'GET http://localhost:%d HTTP/1.1' %
                                        self.http_server_port) + proxy.CRLF
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.LINE_RCVD)
        self.assertNotEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)

        # Send headers and blank line, thus completing HTTP request
        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ])
        self.assert_data_queued(mock_server_connection, server)
        self.proxy.run_once()
        server.flush.assert_called_once()

    def assert_tunnel_response(
            self, mock_server_connection: mock.Mock, server: mock.Mock) -> None:
        self.proxy.run_once()
        self.assertTrue(
            self.proxy.plugins['HttpProxyPlugin'].server is not None)  # type: ignore
        self.assertEqual(
            self.proxy.client.buffer,
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.queue.assert_not_called()
        server.closed = False

        parser = proxy.HttpParser(proxy.httpParserTypes.RESPONSE_PARSER)
        parser.parse(self.proxy.client.buffer)
        self.assertEqual(parser.state, proxy.httpParserStates.COMPLETE)
        assert parser.code is not None
        self.assertEqual(int(parser.code), 200)

    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_http_tunnel(self, mock_server_connection: mock.Mock,
                         mock_select: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True
        server.has_buffer.side_effect = [False, False, False, True]
        mock_select.side_effect = [
            ([self._conn], [], []),         # client read ready
            ([], [self._conn], []),         # client write ready
            ([self._conn], [], []),         # client read ready
            ([], [server.connection], [])   # server write ready
        ]

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            proxy.CRLF
        ])
        self.assert_tunnel_response(mock_server_connection, server)

        # Dispatch tunnel established response to client
        self.proxy.run_once()
        self.assert_data_queued_to_server(server)

        self.proxy.run_once()
        self.assertEqual(server.queue.call_count, 1)
        server.flush.assert_called_once()

    @mock.patch('select.select')
    def test_proxy_connection_failed(self, mock_select: mock.Mock) -> None:
        mock_select.return_value = ([self._conn], [], [])
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET http://unknown.domain HTTP/1.1',
            b'Host: unknown.domain',
            proxy.CRLF
        ])
        self.proxy.run_once()
        received = self._conn.send.call_args[0][0]
        self.assertEqual(received, proxy.ProxyConnectionFailed.RESPONSE_PKT)

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    def test_proxy_authentication_failed(
            self, mock_select: mock.Mock, mock_fromfd: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        mock_select.return_value = ([self._conn], [], [])
        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET http://abhinavsingh.com HTTP/1.1',
            b'Host: abhinavsingh.com',
            proxy.CRLF
        ])
        self.proxy.run_once()
        self.assertEqual(
            self._conn.send.call_args[0][0],
            proxy.ProxyAuthenticationFailed.RESPONSE_PKT)

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_get(
            self, mock_server_connection: mock.Mock,
            mock_select: mock.Mock,
            mock_fromfd: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        mock_select.return_value = ([self._conn], [], [])
        server = mock_server_connection.return_value
        server.connect.return_value = True

        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, addr=self._addr, config=config)
        assert self.http_server_port is not None

        self._conn.recv.return_value = b'GET http://localhost:%d HTTP/1.1' % self.http_server_port
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.INITIALIZED)

        self._conn.recv.return_value = proxy.CRLF
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.LINE_RCVD)

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ])
        self.assert_data_queued(mock_server_connection, server)

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    @mock.patch('proxy.TcpServerConnection')
    def test_authenticated_proxy_http_tunnel(
            self, mock_server_connection: mock.Mock,
            mock_select: mock.Mock,
            mock_fromfd: mock.Mock) -> None:
        server = mock_server_connection.return_value
        server.connect.return_value = True

        self._conn = mock_fromfd.return_value
        mock_select.side_effect = [
            ([self._conn], [], []), ([self._conn], [], []), ([], [server.connection], [])]

        config = proxy.ProtocolConfig(
            auth_code=b'Basic %s' %
                      base64.b64encode(b'user:pass'))
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')

        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)

        assert self.http_server_port is not None
        self._conn.recv.return_value = proxy.CRLF.join([
            b'CONNECT localhost:%d HTTP/1.1' % self.http_server_port,
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Proxy-Connection: Keep-Alive',
            b'Proxy-Authorization: Basic dXNlcjpwYXNz',
            proxy.CRLF
        ])
        self.assert_tunnel_response(mock_server_connection, server)
        self.proxy.client.flush()
        self.assert_data_queued_to_server(server)

        self.proxy.run_once()
        server.flush.assert_called_once()

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    def test_pac_file_served_from_disk(
            self, mock_select: mock.Mock, mock_fromfd: mock.Mock) -> None:
        pac_file = 'proxy.pac'
        self._conn = mock_fromfd.return_value
        mock_select.return_value = [self._conn], [], []
        self.init_and_make_pac_file_request(pac_file)
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        with open('proxy.pac', 'rb') as f:
            self._conn.send.called_once_with(proxy.HttpParser.build_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                    b'Connection': b'close'
                }, body=f.read()
            ))

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    def test_pac_file_served_from_buffer(
            self, mock_select: mock.Mock, mock_fromfd: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        pac_file_content = b'function FindProxyForURL(url, host) { return "PROXY localhost:8899; DIRECT"; }'
        mock_select.return_value = [self._conn], [], []
        self.init_and_make_pac_file_request(proxy.text_(pac_file_content))
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        self._conn.send.called_once_with(proxy.HttpParser.build_response(
            200, reason=b'OK', headers={
                b'Content-Type': b'application/x-ns-proxy-autoconfig',
                b'Connection': b'close'
            }, body=pac_file_content
        ))

    @mock.patch('socket.fromfd')
    @mock.patch('select.select')
    def test_default_web_server_returns_404(
            self, mock_select: mock.Mock, mock_fromfd: mock.Mock) -> None:
        self._conn = mock_fromfd.return_value
        mock_select.return_value = [self._conn], [], []
        config = proxy.ProtocolConfig()
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET /hello HTTP/1.1',
            proxy.CRLF,
            proxy.CRLF
        ])
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        self.assertEqual(
            self._conn.send.call_args[0][0],
            proxy.HttpWebServerPlugin.DEFAULT_404_RESPONSE)

    @mock.patch('socket.fromfd')
    def test_on_client_connection_called_on_teardown(
            self, mock_fromfd: mock.Mock) -> None:
        config = proxy.ProtocolConfig()
        plugin = mock.MagicMock()
        config.plugins = {b'ProtocolHandlerPlugin': [plugin]}
        self._conn = mock_fromfd.return_value
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        plugin.assert_called()
        with mock.patch.object(self.proxy, 'run_once') as mock_run_once:
            mock_run_once.return_value = True
            self.proxy.run()
        self.assertTrue(self._conn.closed)
        plugin.return_value.access_log.assert_called()
        plugin.return_value.on_client_connection_close.assert_called()

    def init_and_make_pac_file_request(self, pac_file: str) -> None:
        config = proxy.ProtocolConfig(pac_file=pac_file)
        config.plugins = proxy.load_plugins(
            b'proxy.HttpProxyPlugin,proxy.HttpWebServerPlugin,proxy.HttpWebServerPacFilePlugin')
        self.proxy = proxy.ProtocolHandler(
            self.fileno, self._addr, config=config)
        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            proxy.CRLF,
        ])

    def assert_data_queued(
            self, mock_server_connection: mock.Mock, server: mock.Mock) -> None:
        self.proxy.run_once()
        self.assertEqual(
            self.proxy.request.state,
            proxy.httpParserStates.COMPLETE)
        mock_server_connection.assert_called_once()
        server.connect.assert_called_once()
        server.closed = False
        assert self.http_server_port is not None
        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'User-Agent: proxy.py/%s' % proxy.version,
            b'Host: localhost:%d' % self.http_server_port,
            b'Accept: */*',
            b'Via: %s' % b'1.1 proxy.py v%s' % proxy.version,
            proxy.CRLF
        ]))

    def assert_data_queued_to_server(self, server: mock.Mock) -> None:
        assert self.http_server_port is not None
        self.assertEqual(
            self._conn.send.call_args[0][0],
            proxy.HttpProxyPlugin.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)

        self._conn.recv.return_value = proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ])
        self.proxy.run_once()
        server.queue.assert_called_once_with(proxy.CRLF.join([
            b'GET / HTTP/1.1',
            b'Host: localhost:%d' % self.http_server_port,
            b'User-Agent: proxy.py/%s' % proxy.version,
            proxy.CRLF
        ]))
        server.flush.assert_not_called()


class TestWorker(unittest.TestCase):

    @mock.patch('proxy.ProtocolHandler')
    def setUp(self, mock_protocol_handler: mock.Mock) -> None:
        self.pipe = multiprocessing.Pipe()
        self.worker = proxy.Worker(
            self.pipe[1],
            mock_protocol_handler,
            config=proxy.ProtocolConfig())
        self.mock_protocol_handler = mock_protocol_handler

    @mock.patch('proxy.ProtocolHandler')
    def test_shutdown_op(self, mock_http_proxy: mock.Mock) -> None:
        self.pipe[0].send((proxy.workerOperations.SHUTDOWN, None))
        self.worker.run()
        self.assertFalse(mock_http_proxy.called)

    @mock.patch('proxy.recv_handle')
    def test_spawns_http_proxy_threads(
            self, mock_recv_handle: mock.Mock) -> None:
        fileno = 10
        mock_recv_handle.return_value = fileno
        self.pipe[0].send((proxy.workerOperations.HTTP_PROTOCOL, None))
        self.pipe[0].send((proxy.workerOperations.SHUTDOWN, None))
        self.worker.run()
        self.assertTrue(self.mock_protocol_handler.called)

    def test_handles_work_queue_recv_connection_refused(self) -> None:
        with mock.patch.object(self.worker.work_queue, 'recv') as mock_recv:
            mock_recv.side_effect = ConnectionRefusedError()
            self.assertFalse(self.worker.run_once())  # doesn't teardown


class TestHttpRequestRejected(unittest.TestCase):

    def setUp(self) -> None:
        self.request = proxy.HttpParser(proxy.httpParserTypes.REQUEST_PARSER)

    def test_empty_response(self) -> None:
        e = proxy.HttpRequestRejected()
        self.assertEqual(e.response(self.request), None)

    def test_status_code_response(self) -> None:
        e = proxy.HttpRequestRejected(status_code=200, reason=b'OK')
        self.assertEqual(e.response(self.request), proxy.CRLF.join([
            b'HTTP/1.1 200 OK',
            proxy.PROXY_AGENT_HEADER,
            proxy.CRLF
        ]))

    def test_body_response(self) -> None:
        e = proxy.HttpRequestRejected(
            status_code=404, reason=b'NOT FOUND',
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
    @mock.patch('proxy.WorkerPool')
    @mock.patch('proxy.logging.basicConfig')
    def test_log_file_setup(
            self,
            mock_config: mock.Mock,
            mock_multicore_dispatcher: mock.Mock,
            mock_set_open_file_limit: mock.Mock) -> None:
        log_file = get_temp_file('proxy.log')
        proxy.main(['--log-file', log_file])
        mock_set_open_file_limit.assert_called()
        mock_multicore_dispatcher.assert_called()
        mock_multicore_dispatcher.return_value.run.assert_called()
        mock_config.assert_called_with(
            filename=log_file,
            filemode='a',
            level=logging.INFO,
            format=proxy.DEFAULT_LOG_FORMAT
        )

    @mock.patch('os.remove')
    @mock.patch('os.path.exists')
    @mock.patch('builtins.open')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.WorkerPool')
    @unittest.skipIf(
        True,  # type: ignore
        'This test passes while development on Intellij but fails via CLI :(')
    def test_pid_file_is_written_and_removed(
            self,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_open,
            mock_exists,
            mock_remove) -> None:
        pid_file = get_temp_file('proxy.pid')
        proxy.main(['--pid-file', pid_file])
        mock_set_open_file_limit.assert_called()
        mock_multicore_dispatcher.assert_called()
        mock_multicore_dispatcher.return_value.run.assert_called()
        mock_open.assert_called_with(pid_file, 'wb')
        mock_open.return_value.__enter__.return_value.write.assert_called_with(
            proxy.bytes_(os.getpid()))
        mock_exists.assert_called_with(pid_file)
        mock_remove.assert_called_with(pid_file)

    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.WorkerPool')
    def test_main(
            self,
            mock_multicore_dispatcher: mock.Mock,
            mock_set_open_file_limit: mock.Mock,
            mock_config: mock.Mock) -> None:
        proxy.main(['--basic-auth', 'user:pass'])
        self.assertTrue(mock_set_open_file_limit.called)
        config = mock_config.return_value
        mock_multicore_dispatcher.assert_called_with(
            hostname=config.hostname,
            port=config.port,
            backlog=config.backlog,
            num_workers=config.num_workers,
            work_klass=proxy.ProtocolHandler,
            config=config)
        mock_config.assert_called_with(
            auth_code=b'Basic dXNlcjpwYXNz',
            client_recvbuf_size=proxy.DEFAULT_CLIENT_RECVBUF_SIZE,
            server_recvbuf_size=proxy.DEFAULT_SERVER_RECVBUF_SIZE,
            pac_file=proxy.DEFAULT_PAC_FILE,
            pac_file_url_path=proxy.DEFAULT_PAC_FILE_URL_PATH,
            disable_headers=proxy.DEFAULT_DISABLE_HEADERS,
            hostname=proxy.DEFAULT_IPV6_HOSTNAME,
            port=proxy.DEFAULT_PORT,
            backlog=proxy.DEFAULT_BACKLOG,
            num_workers=multiprocessing.cpu_count(),
            keyfile=None,
            certfile=None,
            ca_cert_file=None,
            ca_key_file=None,
            ca_signing_key_file=None,
            ca_cert_dir=None
        )

    @mock.patch('builtins.print')
    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.WorkerPool')
    def test_main_version(
            self,
            mock_multicore_dispatcher: mock.Mock,
            mock_set_open_file_limit: mock.Mock,
            mock_config: mock.Mock,
            mock_print: mock.Mock) -> None:
        with self.assertRaises(SystemExit):
            proxy.main(['--version'])
            mock_print.assert_called_with(proxy.text_(proxy.version))
        mock_multicore_dispatcher.assert_not_called()
        mock_set_open_file_limit.assert_not_called()
        mock_config.assert_not_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.WorkerPool')
    @mock.patch('proxy.is_py3')
    def test_main_py3_runs(
            self,
            mock_is_py3: mock.Mock,
            mock_multicore_dispatcher: mock.Mock,
            mock_set_open_file_limit: mock.Mock,
            mock_config: mock.Mock,
            mock_print: mock.Mock) -> None:
        mock_is_py3.return_value = True
        proxy.main([])
        mock_is_py3.assert_called()
        mock_print.assert_not_called()
        mock_multicore_dispatcher.assert_called()
        mock_set_open_file_limit.assert_called()
        mock_config.assert_called()

    @mock.patch('builtins.print')
    @mock.patch('proxy.ProtocolConfig')
    @mock.patch('proxy.set_open_file_limit')
    @mock.patch('proxy.WorkerPool')
    @mock.patch('proxy.is_py3')
    @unittest.skipIf(
        True,  # type: ignore
        'This test passes while development on Intellij but fails via CLI :(')
    def test_main_py2_exit(
            self,
            mock_is_py3,
            mock_multicore_dispatcher,
            mock_set_open_file_limit,
            mock_config,
            mock_print) -> None:
        mock_is_py3.return_value = False
        with self.assertRaises(SystemExit):
            proxy.main([])
            mock_print.assert_called_with('DEPRECATION')
            mock_is_py3.assert_called()
        mock_multicore_dispatcher.assert_not_called()
        mock_set_open_file_limit.assert_not_called()
        mock_config.assert_not_called()

    def test_text(self) -> None:
        self.assertEqual(proxy.text_(b'hello'), 'hello')

    def test_text_int(self) -> None:
        self.assertEqual(proxy.text_(1), '1')

    def test_text_nochange(self) -> None:
        self.assertEqual(proxy.text_('hello'), 'hello')

    def test_bytes(self) -> None:
        self.assertEqual(proxy.bytes_('hello'), b'hello')

    def test_bytes_int(self) -> None:
        self.assertEqual(proxy.bytes_(1), b'1')

    def test_bytes_nochange(self) -> None:
        self.assertEqual(proxy.bytes_(b'hello'), b'hello')

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(128, 1024))  # type: ignore
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit(
            self, mock_set_rlimit, mock_get_rlimit) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_called_with(resource.RLIMIT_NOFILE, (256, 1024))

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(256, 1024))  # type: ignore
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called(
            self, mock_set_rlimit, mock_get_rlimit) -> None:
        proxy.set_open_file_limit(256)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()

    @unittest.skipIf(
        os.name == 'nt',
        'Open file limit tests disabled for Windows')
    @mock.patch('resource.getrlimit', return_value=(256, 1024))  # type: ignore
    @mock.patch('resource.setrlimit', return_value=None)
    def test_set_open_file_limit_not_called1(
            self, mock_set_rlimit, mock_get_rlimit) -> None:
        proxy.set_open_file_limit(1024)
        mock_get_rlimit.assert_called_with(resource.RLIMIT_NOFILE)
        mock_set_rlimit.assert_not_called()


if __name__ == '__main__':
    proxy.UNDER_TEST = True
    unittest.main()
